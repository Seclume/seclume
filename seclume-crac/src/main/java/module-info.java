/**
 * Checkpoint and restore for seclume pools - see {@link space.seclume.crac.SeclumeCrac}.
 */
module seclume.crac {

    requires transitive seclume.pool;
    requires org.crac;

    exports space.seclume.crac;
}
