/**
 * Checkpoint and restore for seclume pools - see {@link space.seclume.crac.SeclumeCrac}.
 */
module seclume.crac {

    requires transitive seclume.pool;
    requires org.crac;
    requires seclume.core;

    exports space.seclume.crac;
}
