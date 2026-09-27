package space.seclume.jasper;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import net.sf.jasperreports.engine.DefaultJasperReportsContext;
import net.sf.jasperreports.engine.JRPrintElement;
import net.sf.jasperreports.engine.JRPrintPage;
import net.sf.jasperreports.engine.JRPrintText;
import net.sf.jasperreports.engine.JasperCompileManager;
import net.sf.jasperreports.engine.JasperFillManager;
import net.sf.jasperreports.engine.JasperPrint;
import net.sf.jasperreports.engine.JasperReport;
import net.sf.jasperreports.engine.design.JRDesignBand;
import net.sf.jasperreports.engine.design.JRDesignExpression;
import net.sf.jasperreports.engine.design.JRDesignField;
import net.sf.jasperreports.engine.design.JRDesignQuery;
import net.sf.jasperreports.engine.design.JRDesignSection;
import net.sf.jasperreports.engine.design.JRDesignTextField;
import net.sf.jasperreports.engine.design.JasperDesign;

import space.seclume.pool.PoolSettings;
import space.seclume.pool.SeclumePool;
import space.seclume.postgresql.jdbc.SeclumeDataSource;
import space.seclume.secret.FileSecretProvider;
import space.seclume.tck.Heap;

/**
 * An application that uses JasperReports the way it is embedded: a report is
 * compiled, filled over a pooled seclume connection, several times, and the
 * pool stays open - then the heap is dumped for the parent to search.
 *
 * <p>The chain is the one the application has in production:
 *
 * <pre>
 *   secret file -> seclume native memory -> seclume JDBC (pooled) -> JasperReports
 * </pre>
 *
 * <p>The connection is handed to {@link JasperFillManager} directly. That is
 * the point: JasperReports' own JDBC data adapters take a password as a
 * {@code String} and pass it as the connection property {@code password},
 * which is exactly what seclume exists to avoid.
 *
 * <p>Mode {@code leaking} is the negative control: the same, plus the mistake
 * an application would make - the password read into a {@code String} and
 * handed to the report as a parameter. The search must find that one, or it
 * proves nothing when it finds nothing.
 *
 * <p>Arguments: {@code <clean|leaking> host port passwordFile dumpFile}.
 */
public final class JasperProbe {

    private JasperProbe() {
    }

    public static void main(String[] args) throws Exception {
        String mode = args[0];
        String host = args[1];
        int port = Integer.parseInt(args[2]);
        Path passwordFile = Path.of(args[3]);
        Path dumpFile = Path.of(args[4]);

        System.setProperty("java.awt.headless", "true");
        DefaultJasperReportsContext context = DefaultJasperReportsContext.getInstance();
        // The JDK's own compiler for the report expressions, so that no
        // further compiler has to be on the class path.
        context.setProperty("net.sf.jasperreports.compiler.java",
                "net.sf.jasperreports.engine.design.JRJdk13Compiler");
        context.setProperty("net.sf.jasperreports.awt.ignore.missing.font", "true");

        JasperReport report = JasperCompileManager.compileReport(design());

        SeclumeDataSource source = new SeclumeDataSource();
        source.setHost(host);
        source.setPort(port);
        source.setDatabase("seclume_test");
        source.setUser("seclume_test");
        source.setSecretProvider(new FileSecretProvider(passwordFile, 256));

        PoolSettings settings = new PoolSettings();
        settings.setName("jasper-proof");
        settings.setMaximumPoolSize(2);
        settings.setConnectionTimeout(Duration.ofSeconds(10));

        Map<String, Object> parameters = new HashMap<>();
        if ("leaking".equals(mode)) {
            // The mistake the negative control makes on purpose.
            parameters.put("password", Files.readString(passwordFile).strip()); // seclume-allow: the negative control
        }

        int rows = 0;
        try (SeclumePool pool = new SeclumePool(source, settings)) {
            for (int run = 0; run < 3; run++) {
                try (Connection connection = pool.getConnection()) {
                    JasperPrint print = JasperFillManager.fillReport(report,
                            new HashMap<>(parameters), connection);
                    rows = countRows(print);
                }
            }
            // The pool stays open with its connection in it, the way an
            // application runs - that session's keys are in the process too.
            Heap.collect();
            Heap.dump(dumpFile);
            if (parameters.get("password") instanceof String kept) {
                System.out.println("kept " + kept.length() + " characters");   // keeps it reachable
            }
            System.out.println("filled 3 reports of " + rows + " rows over seclume, pool open");
        }
    }

    /** One detail band with one text field; the rows come from the server. */
    private static JasperDesign design() throws Exception {
        JasperDesign design = new JasperDesign();
        design.setName("seclume_proof");
        design.setPageWidth(595);
        design.setPageHeight(842);
        design.setColumnWidth(515);
        design.setLeftMargin(40);
        design.setRightMargin(40);
        design.setTopMargin(30);
        design.setBottomMargin(30);

        JRDesignQuery query = new JRDesignQuery();
        query.setText("select 'Zeile ' || n as label from generate_series(1, 50) as n");
        design.setQuery(query);

        JRDesignField label = new JRDesignField();
        label.setName("label");
        label.setValueClass(String.class);
        design.addField(label);

        JRDesignTextField text = new JRDesignTextField();
        text.setX(0);
        text.setY(0);
        text.setWidth(515);
        text.setHeight(15);
        text.setExpression(new JRDesignExpression("$F{label}"));

        JRDesignBand detail = new JRDesignBand();
        detail.setHeight(15);
        detail.addElement(text);
        ((JRDesignSection) design.getDetailSection()).addBand(detail);
        return design;
    }

    /** How many of the printed texts are rows of the query. */
    private static int countRows(JasperPrint print) {
        int rows = 0;
        for (JRPrintPage page : print.getPages()) {
            for (JRPrintElement element : page.getElements()) {
                if (element instanceof JRPrintText text && text.getFullText() != null
                        && text.getFullText().startsWith("Zeile ")) {
                    rows++;
                }
            }
        }
        return rows;
    }
}
