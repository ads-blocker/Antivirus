namespace Edr
{
    /// <summary>Threat severity for layered response. Low=log only; Medium=block (suspend); High=kill; Critical=kill+escalate.</summary>
    public enum ThreatLevel
    {
        Low,     // Log only
        Medium,  // Log + block (suspend process)
        High,    // Log + kill
        Critical // Log + kill (highest confidence)
    }
}
