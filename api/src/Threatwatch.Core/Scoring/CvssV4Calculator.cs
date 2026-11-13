namespace Threatwatch.Core.Scoring;

/// <summary>
/// Computes the CVSS v4.0 base score (or threat/environmental score, when those metrics are present)
/// from a vector string. A port of the FIRST reference calculator (BSD-2-Clause,
/// https://github.com/FIRSTdotorg/cvss-v4-calculator): the vector is reduced to a six-digit
/// MacroVector, scored from a lookup table, then adjusted by its severity distance within the
/// MacroVector.
/// </summary>
public static class CvssV4Calculator
{
    private const double Step = 0.1;

    private static readonly string[] BaseMetrics = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"];

    private static readonly Dictionary<string, string[]> ValidValues = new()
    {
        ["AV"] = ["N", "A", "L", "P"],
        ["AC"] = ["L", "H"],
        ["AT"] = ["N", "P"],
        ["PR"] = ["N", "L", "H"],
        ["UI"] = ["N", "P", "A"],
        ["VC"] = ["H", "L", "N"],
        ["VI"] = ["H", "L", "N"],
        ["VA"] = ["H", "L", "N"],
        ["SC"] = ["H", "L", "N"],
        ["SI"] = ["H", "L", "N"],
        ["SA"] = ["H", "L", "N"],
        ["E"] = ["X", "A", "P", "U"],
        ["CR"] = ["X", "H", "M", "L"],
        ["IR"] = ["X", "H", "M", "L"],
        ["AR"] = ["X", "H", "M", "L"],
        ["MAV"] = ["X", "N", "A", "L", "P"],
        ["MAC"] = ["X", "L", "H"],
        ["MAT"] = ["X", "N", "P"],
        ["MPR"] = ["X", "N", "L", "H"],
        ["MUI"] = ["X", "N", "P", "A"],
        ["MVC"] = ["X", "H", "L", "N"],
        ["MVI"] = ["X", "H", "L", "N"],
        ["MVA"] = ["X", "H", "L", "N"],
        ["MSC"] = ["X", "H", "L", "N"],
        ["MSI"] = ["X", "S", "H", "L", "N"],
        ["MSA"] = ["X", "S", "H", "L", "N"],
    };

    private static readonly Dictionary<string, double> AvLevels = new() { ["N"] = 0.0, ["A"] = 0.1, ["L"] = 0.2, ["P"] = 0.3 };
    private static readonly Dictionary<string, double> PrLevels = new() { ["N"] = 0.0, ["L"] = 0.1, ["H"] = 0.2 };
    private static readonly Dictionary<string, double> UiLevels = new() { ["N"] = 0.0, ["P"] = 0.1, ["A"] = 0.2 };
    private static readonly Dictionary<string, double> AcLevels = new() { ["L"] = 0.0, ["H"] = 0.1 };
    private static readonly Dictionary<string, double> AtLevels = new() { ["N"] = 0.0, ["P"] = 0.1 };
    private static readonly Dictionary<string, double> VLevels = new() { ["H"] = 0.0, ["L"] = 0.1, ["N"] = 0.2 };
    private static readonly Dictionary<string, double> ScLevels = new() { ["H"] = 0.1, ["L"] = 0.2, ["N"] = 0.3 };
    private static readonly Dictionary<string, double> SiSaLevels = new() { ["S"] = 0.0, ["H"] = 0.1, ["L"] = 0.2, ["N"] = 0.3 };
    private static readonly Dictionary<string, double> RLevels = new() { ["H"] = 0.0, ["M"] = 0.1, ["L"] = 0.2 };

    // Highest-severity vectors per EQ level, as metric:value pairs.
    private static readonly string[][] Eq1Max =
    [
        ["AV:N/PR:N/UI:N"],
        ["AV:A/PR:N/UI:N", "AV:N/PR:L/UI:N", "AV:N/PR:N/UI:P"],
        ["AV:P/PR:N/UI:N", "AV:A/PR:L/UI:P"],
    ];

    private static readonly string[][] Eq2Max =
    [
        ["AC:L/AT:N"],
        ["AC:H/AT:N", "AC:L/AT:P"],
    ];

    // Indexed [eq3][eq6].
    private static readonly string[][][] Eq3Eq6Max =
    [
        [
            ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H"],
            ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M"],
        ],
        [
            ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H"],
            ["VC:L/VI:H/VA:L/CR:H/IR:M/AR:H", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M", "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H", "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M"],
        ],
        [
            [],
            ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H"],
        ],
    ];

    private static readonly string[][] Eq4Max =
    [
        ["SC:H/SI:S/SA:S"],
        ["SC:H/SI:H/SA:H"],
        ["SC:L/SI:L/SA:L"],
    ];

    private static readonly double[] Eq1Depth = [1, 4, 5];
    private static readonly double[] Eq2Depth = [1, 2];
    private static readonly double[][] Eq3Eq6Depth = [[7, 6], [8, 8], [0, 10]];
    private static readonly double[] Eq4Depth = [6, 5, 4];

    /// <summary>Scores a CVSS:4.0 vector, or returns null if it is not a complete, valid v4.0 vector.</summary>
    public static decimal? ScoreV4(string? vector)
    {
        if (string.IsNullOrWhiteSpace(vector)
            || !vector.StartsWith("CVSS:4.0/", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var metrics = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in vector.Split('/').Skip(1))
        {
            var kv = part.Split(':');
            if (kv.Length != 2 || metrics.ContainsKey(kv[0])) return null;
            metrics[kv[0]] = kv[1].ToUpperInvariant();
        }

        foreach (var required in BaseMetrics)
        {
            if (!metrics.ContainsKey(required)) return null;
        }

        foreach (var (key, value) in metrics)
        {
            // Supplemental metrics (S, AU, R, V, RE, U) do not affect the score.
            if (ValidValues.TryGetValue(key.ToUpperInvariant(), out var allowed) && !allowed.Contains(value))
            {
                return null;
            }
        }

        var score = Score(metrics);
        return score is { } s ? (decimal)s : null;
    }

    private static double? Score(Dictionary<string, string> cvss)
    {
        if (new[] { "VC", "VI", "VA", "SC", "SI", "SA" }.All(k => M(cvss, k) == "N")) return 0.0;

        var macro = MacroVector(cvss);
        if (!Lookup.TryGetValue(macro, out var value)) return null;

        int eq1 = macro[0] - '0', eq2 = macro[1] - '0', eq3 = macro[2] - '0';
        int eq4 = macro[3] - '0', eq5 = macro[4] - '0', eq6 = macro[5] - '0';

        double Next(int a, int b, int c, int d, int e, int f)
            => Lookup.TryGetValue($"{a}{b}{c}{d}{e}{f}", out var v) ? v : double.NaN;

        var scoreEq1Next = Next(eq1 + 1, eq2, eq3, eq4, eq5, eq6);
        var scoreEq2Next = Next(eq1, eq2 + 1, eq3, eq4, eq5, eq6);

        double scoreEq3Eq6Next;
        if (eq3 == 1 && eq6 == 1) scoreEq3Eq6Next = Next(eq1, eq2, eq3 + 1, eq4, eq5, eq6);
        else if (eq3 == 0 && eq6 == 1) scoreEq3Eq6Next = Next(eq1, eq2, eq3 + 1, eq4, eq5, eq6);
        else if (eq3 == 1 && eq6 == 0) scoreEq3Eq6Next = Next(eq1, eq2, eq3, eq4, eq5, eq6 + 1);
        else if (eq3 == 0 && eq6 == 0)
        {
            var left = Next(eq1, eq2, eq3, eq4, eq5, eq6 + 1);
            var right = Next(eq1, eq2, eq3 + 1, eq4, eq5, eq6);
            scoreEq3Eq6Next = left > right ? left : right;
        }
        else scoreEq3Eq6Next = Next(eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1);

        var scoreEq4Next = Next(eq1, eq2, eq3, eq4 + 1, eq5, eq6);
        var scoreEq5Next = Next(eq1, eq2, eq3, eq4, eq5 + 1, eq6);

        var (distEq1, distEq2, distEq3Eq6, distEq4) = SeverityDistances(cvss, eq1, eq2, eq3, eq4, eq6);

        var lower = 0;
        double mean = 0;

        void Add(double next, double distance, double depth)
        {
            var available = value - next;
            if (double.IsNaN(available)) return;
            lower++;
            mean += available * (distance / (depth * Step));
        }

        Add(scoreEq1Next, distEq1, Eq1Depth[eq1]);
        Add(scoreEq2Next, distEq2, Eq2Depth[eq2]);
        Add(scoreEq3Eq6Next, distEq3Eq6, Eq3Eq6Depth[eq3][eq6]);
        Add(scoreEq4Next, distEq4, Eq4Depth[eq4]);
        if (!double.IsNaN(value - scoreEq5Next)) lower++; // EQ5 always contributes 0 of its distance.

        var result = lower == 0 ? value : value - mean / lower;
        result = Math.Clamp(result, 0.0, 10.0);
        return Math.Round(result * 10, MidpointRounding.AwayFromZero) / 10;
    }

    /// <summary>
    /// The scored vector's distance from a highest-severity vector in its MacroVector, per EQ.
    /// The first candidate it does not exceed in any metric is used.
    /// </summary>
    private static (double Eq1, double Eq2, double Eq3Eq6, double Eq4) SeverityDistances(
        Dictionary<string, string> cvss, int eq1, int eq2, int eq3, int eq4, int eq6)
    {
        double dAv = 0, dPr = 0, dUi = 0, dAc = 0, dAt = 0, dVc = 0, dVi = 0, dVa = 0, dSc = 0, dSi = 0, dSa = 0, dCr = 0, dIr = 0, dAr = 0;
        foreach (var m1 in Eq1Max[eq1])
        foreach (var m2 in Eq2Max[eq2])
        foreach (var m36 in Eq3Eq6Max[eq3][eq6])
        foreach (var m4 in Eq4Max[eq4])
        {
            var max = ParseMax($"{m1}/{m2}/{m36}/{m4}");
            dAv = AvLevels[M(cvss, "AV")] - AvLevels[max["AV"]];
            dPr = PrLevels[M(cvss, "PR")] - PrLevels[max["PR"]];
            dUi = UiLevels[M(cvss, "UI")] - UiLevels[max["UI"]];
            dAc = AcLevels[M(cvss, "AC")] - AcLevels[max["AC"]];
            dAt = AtLevels[M(cvss, "AT")] - AtLevels[max["AT"]];
            dVc = VLevels[M(cvss, "VC")] - VLevels[max["VC"]];
            dVi = VLevels[M(cvss, "VI")] - VLevels[max["VI"]];
            dVa = VLevels[M(cvss, "VA")] - VLevels[max["VA"]];
            dSc = ScLevels[M(cvss, "SC")] - ScLevels[max["SC"]];
            dSi = SiSaLevels[M(cvss, "SI")] - SiSaLevels[max["SI"]];
            dSa = SiSaLevels[M(cvss, "SA")] - SiSaLevels[max["SA"]];
            dCr = RLevels[M(cvss, "CR")] - RLevels[max["CR"]];
            dIr = RLevels[M(cvss, "IR")] - RLevels[max["IR"]];
            dAr = RLevels[M(cvss, "AR")] - RLevels[max["AR"]];

            if (new[] { dAv, dPr, dUi, dAc, dAt, dVc, dVi, dVa, dSc, dSi, dSa, dCr, dIr, dAr }.All(d => d >= 0)) goto done;
        }

        done:
        return (dAv + dPr + dUi, dAc + dAt, dVc + dVi + dVa + dCr + dIr + dAr, dSc + dSi + dSa);
    }

    private static Dictionary<string, string> ParseMax(string vector)
    {
        var d = new Dictionary<string, string>();
        foreach (var part in vector.Split('/'))
        {
            var kv = part.Split(':');
            d[kv[0]] = kv[1];
        }

        return d;
    }

    /// <summary>A metric's effective value: a modified (M-prefixed) metric overrides the base one, and unset threat/requirement metrics assume the worst case.</summary>
    private static string M(Dictionary<string, string> cvss, string metric)
    {
        var selected = cvss.GetValueOrDefault(metric, "X");
        if (metric == "E" && selected == "X") return "A";
        if (metric is "CR" or "IR" or "AR" && selected == "X") return "H";

        if (cvss.TryGetValue("M" + metric, out var modified) && modified != "X") return modified;
        return selected;
    }

    private static string MacroVector(Dictionary<string, string> c)
    {
        string av = M(c, "AV"), pr = M(c, "PR"), ui = M(c, "UI");
        int eq1 = av == "N" && pr == "N" && ui == "N" ? 0
            : (av == "N" || pr == "N" || ui == "N") && av != "P" ? 1
            : 2;

        int eq2 = M(c, "AC") == "L" && M(c, "AT") == "N" ? 0 : 1;

        string vc = M(c, "VC"), vi = M(c, "VI"), va = M(c, "VA");
        int eq3 = vc == "H" && vi == "H" ? 0
            : vc == "H" || vi == "H" || va == "H" ? 1
            : 2;

        int eq4 = M(c, "MSI") == "S" || M(c, "MSA") == "S" ? 0
            : M(c, "SC") == "H" || M(c, "SI") == "H" || M(c, "SA") == "H" ? 1
            : 2;

        int eq5 = M(c, "E") switch { "A" => 0, "P" => 1, _ => 2 };

        int eq6 = (M(c, "CR") == "H" && vc == "H") || (M(c, "IR") == "H" && vi == "H") || (M(c, "AR") == "H" && va == "H") ? 0 : 1;

        return $"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}";
    }

    private static readonly Dictionary<string, double> Lookup = new()
    {
        ["000000"] = 10.0,
        ["000001"] = 9.9,
        ["000010"] = 9.8,
        ["000011"] = 9.5,
        ["000020"] = 9.5,
        ["000021"] = 9.2,
        ["000100"] = 10.0,
        ["000101"] = 9.6,
        ["000110"] = 9.3,
        ["000111"] = 8.7,
        ["000120"] = 9.1,
        ["000121"] = 8.1,
        ["000200"] = 9.3,
        ["000201"] = 9.0,
        ["000210"] = 8.9,
        ["000211"] = 8.0,
        ["000220"] = 8.1,
        ["000221"] = 6.8,
        ["001000"] = 9.8,
        ["001001"] = 9.5,
        ["001010"] = 9.5,
        ["001011"] = 9.2,
        ["001020"] = 9.0,
        ["001021"] = 8.4,
        ["001100"] = 9.3,
        ["001101"] = 9.2,
        ["001110"] = 8.9,
        ["001111"] = 8.1,
        ["001120"] = 8.1,
        ["001121"] = 6.5,
        ["001200"] = 8.8,
        ["001201"] = 8.0,
        ["001210"] = 7.8,
        ["001211"] = 7.0,
        ["001220"] = 6.9,
        ["001221"] = 4.8,
        ["002001"] = 9.2,
        ["002011"] = 8.2,
        ["002021"] = 7.2,
        ["002101"] = 7.9,
        ["002111"] = 6.9,
        ["002121"] = 5.0,
        ["002201"] = 6.9,
        ["002211"] = 5.5,
        ["002221"] = 2.7,
        ["010000"] = 9.9,
        ["010001"] = 9.7,
        ["010010"] = 9.5,
        ["010011"] = 9.2,
        ["010020"] = 9.2,
        ["010021"] = 8.5,
        ["010100"] = 9.5,
        ["010101"] = 9.1,
        ["010110"] = 9.0,
        ["010111"] = 8.3,
        ["010120"] = 8.4,
        ["010121"] = 7.1,
        ["010200"] = 9.2,
        ["010201"] = 8.1,
        ["010210"] = 8.2,
        ["010211"] = 7.1,
        ["010220"] = 7.2,
        ["010221"] = 5.3,
        ["011000"] = 9.5,
        ["011001"] = 9.3,
        ["011010"] = 9.2,
        ["011011"] = 8.5,
        ["011020"] = 8.5,
        ["011021"] = 7.3,
        ["011100"] = 9.2,
        ["011101"] = 8.2,
        ["011110"] = 8.0,
        ["011111"] = 7.2,
        ["011120"] = 7.0,
        ["011121"] = 5.9,
        ["011200"] = 8.4,
        ["011201"] = 7.0,
        ["011210"] = 7.1,
        ["011211"] = 5.2,
        ["011220"] = 5.0,
        ["011221"] = 3.0,
        ["012001"] = 8.6,
        ["012011"] = 7.5,
        ["012021"] = 5.2,
        ["012101"] = 7.1,
        ["012111"] = 5.2,
        ["012121"] = 2.9,
        ["012201"] = 6.3,
        ["012211"] = 2.9,
        ["012221"] = 1.7,
        ["100000"] = 9.8,
        ["100001"] = 9.5,
        ["100010"] = 9.4,
        ["100011"] = 8.7,
        ["100020"] = 9.1,
        ["100021"] = 8.1,
        ["100100"] = 9.4,
        ["100101"] = 8.9,
        ["100110"] = 8.6,
        ["100111"] = 7.4,
        ["100120"] = 7.7,
        ["100121"] = 6.4,
        ["100200"] = 8.7,
        ["100201"] = 7.5,
        ["100210"] = 7.4,
        ["100211"] = 6.3,
        ["100220"] = 6.3,
        ["100221"] = 4.9,
        ["101000"] = 9.4,
        ["101001"] = 8.9,
        ["101010"] = 8.8,
        ["101011"] = 7.7,
        ["101020"] = 7.6,
        ["101021"] = 6.7,
        ["101100"] = 8.6,
        ["101101"] = 7.6,
        ["101110"] = 7.4,
        ["101111"] = 5.8,
        ["101120"] = 5.9,
        ["101121"] = 5.0,
        ["101200"] = 7.2,
        ["101201"] = 5.7,
        ["101210"] = 5.7,
        ["101211"] = 5.2,
        ["101220"] = 5.2,
        ["101221"] = 2.5,
        ["102001"] = 8.3,
        ["102011"] = 7.0,
        ["102021"] = 5.4,
        ["102101"] = 6.5,
        ["102111"] = 5.8,
        ["102121"] = 2.6,
        ["102201"] = 5.3,
        ["102211"] = 2.1,
        ["102221"] = 1.3,
        ["110000"] = 9.5,
        ["110001"] = 9.0,
        ["110010"] = 8.8,
        ["110011"] = 7.6,
        ["110020"] = 7.6,
        ["110021"] = 7.0,
        ["110100"] = 9.0,
        ["110101"] = 7.7,
        ["110110"] = 7.5,
        ["110111"] = 6.2,
        ["110120"] = 6.1,
        ["110121"] = 5.3,
        ["110200"] = 7.7,
        ["110201"] = 6.6,
        ["110210"] = 6.8,
        ["110211"] = 5.9,
        ["110220"] = 5.2,
        ["110221"] = 3.0,
        ["111000"] = 8.9,
        ["111001"] = 7.8,
        ["111010"] = 7.6,
        ["111011"] = 6.7,
        ["111020"] = 6.2,
        ["111021"] = 5.8,
        ["111100"] = 7.4,
        ["111101"] = 5.9,
        ["111110"] = 5.7,
        ["111111"] = 5.7,
        ["111120"] = 4.7,
        ["111121"] = 2.3,
        ["111200"] = 6.1,
        ["111201"] = 5.2,
        ["111210"] = 5.7,
        ["111211"] = 2.9,
        ["111220"] = 2.4,
        ["111221"] = 1.6,
        ["112001"] = 7.1,
        ["112011"] = 5.9,
        ["112021"] = 3.0,
        ["112101"] = 5.8,
        ["112111"] = 2.6,
        ["112121"] = 1.5,
        ["112201"] = 2.3,
        ["112211"] = 1.3,
        ["112221"] = 0.6,
        ["200000"] = 9.3,
        ["200001"] = 8.7,
        ["200010"] = 8.6,
        ["200011"] = 7.2,
        ["200020"] = 7.5,
        ["200021"] = 5.8,
        ["200100"] = 8.6,
        ["200101"] = 7.4,
        ["200110"] = 7.4,
        ["200111"] = 6.1,
        ["200120"] = 5.6,
        ["200121"] = 3.4,
        ["200200"] = 7.0,
        ["200201"] = 5.4,
        ["200210"] = 5.2,
        ["200211"] = 4.0,
        ["200220"] = 4.0,
        ["200221"] = 2.2,
        ["201000"] = 8.5,
        ["201001"] = 7.5,
        ["201010"] = 7.4,
        ["201011"] = 5.5,
        ["201020"] = 6.2,
        ["201021"] = 5.1,
        ["201100"] = 7.2,
        ["201101"] = 5.7,
        ["201110"] = 5.5,
        ["201111"] = 4.1,
        ["201120"] = 4.6,
        ["201121"] = 1.9,
        ["201200"] = 5.3,
        ["201201"] = 3.6,
        ["201210"] = 3.4,
        ["201211"] = 1.9,
        ["201220"] = 1.9,
        ["201221"] = 0.8,
        ["202001"] = 6.4,
        ["202011"] = 5.1,
        ["202021"] = 2.0,
        ["202101"] = 4.7,
        ["202111"] = 2.1,
        ["202121"] = 1.1,
        ["202201"] = 2.4,
        ["202211"] = 0.9,
        ["202221"] = 0.4,
        ["210000"] = 8.8,
        ["210001"] = 7.5,
        ["210010"] = 7.3,
        ["210011"] = 5.3,
        ["210020"] = 6.0,
        ["210021"] = 5.0,
        ["210100"] = 7.3,
        ["210101"] = 5.5,
        ["210110"] = 5.9,
        ["210111"] = 4.0,
        ["210120"] = 4.1,
        ["210121"] = 2.0,
        ["210200"] = 5.4,
        ["210201"] = 4.3,
        ["210210"] = 4.5,
        ["210211"] = 2.2,
        ["210220"] = 2.0,
        ["210221"] = 1.1,
        ["211000"] = 7.5,
        ["211001"] = 5.5,
        ["211010"] = 5.8,
        ["211011"] = 4.5,
        ["211020"] = 4.0,
        ["211021"] = 2.1,
        ["211100"] = 6.1,
        ["211101"] = 5.1,
        ["211110"] = 4.8,
        ["211111"] = 1.8,
        ["211120"] = 2.0,
        ["211121"] = 0.9,
        ["211200"] = 4.6,
        ["211201"] = 1.8,
        ["211210"] = 1.7,
        ["211211"] = 0.7,
        ["211220"] = 0.8,
        ["211221"] = 0.2,
        ["212001"] = 5.3,
        ["212011"] = 2.4,
        ["212021"] = 1.4,
        ["212101"] = 2.4,
        ["212111"] = 1.2,
        ["212121"] = 0.5,
        ["212201"] = 1.0,
        ["212211"] = 0.3,
        ["212221"] = 0.1,
    };
}
