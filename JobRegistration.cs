using System;

namespace Edr
{
    public static class JobRegistration
    {
        public static void RegisterAll(JobRunner runner)
        {
            if (runner == null) return;
            runner.Register(new JobHashDetection());
            runner.Register(new JobLOLBinDetection());
            runner.Register(new JobProcessAnomalyDetection());
            runner.Register(new JobAMSIBypassDetection());
            runner.Register(new JobCredentialDumpDetection());
            // runner.Register(new JobCredentialProtection());  // Disabled: permanent auditpol + credential clearing causes persistent system slowness
            runner.Register(new JobWMIPersistenceDetection());
            runner.Register(new JobScheduledTaskDetection());
            runner.Register(new JobRegistryPersistenceDetection());
            runner.Register(new JobDLLHijackingDetection());
            runner.Register(new JobTokenManipulationDetection());
            runner.Register(new JobProcessHollowingDetection());
            runner.Register(new JobKeyloggerDetection());
            runner.Register(new JobKeyScramblerManagement());
            runner.Register(new JobRansomwareDetection());
            runner.Register(new JobNetworkAnomalyDetection());
            runner.Register(new JobNetworkTrafficMonitoring());
            runner.Register(new JobRootkitDetection());
            runner.Register(new JobClipboardMonitoring());
            runner.Register(new JobCOMMonitoring());
            runner.Register(new JobBrowserExtensionMonitoring());
            runner.Register(new JobShadowCopyMonitoring());
            runner.Register(new JobUSBMonitoring());
            runner.Register(new JobMobileDeviceMonitoring());
            runner.Register(new JobAttackToolsDetection());
            runner.Register(new JobAdvancedThreatDetection());
            runner.Register(new JobEventLogMonitoring());
            runner.Register(new JobFirewallRuleMonitoring());
            runner.Register(new JobServiceMonitoring());
            runner.Register(new JobFilelessDetection());
            runner.Register(new JobMemoryScanning());
            runner.Register(new JobNamedPipeMonitoring());
            runner.Register(new JobDNSExfiltrationDetection());
            runner.Register(new JobWebcamGuardian());
            runner.Register(new JobBeaconDetection());
            runner.Register(new JobCodeInjectionDetection());
            runner.Register(new JobDataExfiltrationDetection());
            runner.Register(new JobFileEntropyDetection());
            runner.Register(new JobHoneypotMonitoring());
            runner.Register(new JobLateralMovementDetection());
            runner.Register(new JobProcessCreationDetection());
            runner.Register(new JobQuarantineManagement());
            runner.Register(new JobReflectiveDLLInjectionDetection());
            runner.Register(new JobSimpleAntivirus());
            runner.Register(new JobResponseEngine());
            runner.Register(new JobPrivacyForgeSpoofing());
            runner.Register(new JobGFocus());
            runner.Register(new JobMitreMapping());
            runner.Register(new JobIdsDetection());
            runner.Register(new JobYaraDetection());
        }
    }
}
