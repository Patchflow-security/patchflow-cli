package benchmark

import (
	"time"
)

// Aggregate computes the benchmark Summary from per-repo results.
//
// Triaged counts (true/false positives, unknown) are derived from per-repo
// Metrics when a review has been recorded. When no triage is available, all
// findings count as "unknown/unreviewed" and precision/noise are not computed
// at the suite level. Recall is aggregated only over repos that declare
// ExpectedFindings.
func Aggregate(results []RepoResult, cfg *Config) *Summary {
	s := &Summary{
		Suite:          cfg.Suite,
		Date:           cfg.Date,
		PerRepo:        make([]Metrics, 0, len(results)),
		ToolComparison: map[string]int{},
	}

	var totalScanTime time.Duration
	var speedups []float64
	var recalls []float64
	var frameworkRecalls []float64
	var precisions []float64
	var noiseRates []float64
	reposWithRecall := 0
	reposWithFrameworkRecall := 0
	reposWithTriage := 0

	for _, res := range results {
		m := res.PatchFlow
		s.PerRepo = append(s.PerRepo, m)
		s.ReposScanned++
		s.TotalLOC += m.LOC
		s.TotalFindings += m.TotalFindings
		s.TotalFrameworkFindings += m.FrameworkFindings

		s.ConfirmedTruePos += m.TruePositives
		s.FalsePositives += m.FalsePositives
		s.UnknownUnreviewed += m.Unknown

		totalScanTime += m.ScanDuration

		if m.SARIFGenerated {
			s.SARIFTotalCount++
			if m.SARIFValid {
				s.SARIFValidCount++
			}
		}
		if m.CacheSpeedup > 0 {
			speedups = append(speedups, m.CacheSpeedup)
		}
		if len(res.Repo.ExpectedFindings) > 0 {
			reposWithRecall++
			recalls = append(recalls, m.Recall)
		}
		if len(res.Repo.ExpectedFrameworkFindings) > 0 {
			reposWithFrameworkRecall++
			frameworkRecalls = append(frameworkRecalls, m.FrameworkRecall)
		}
		if m.TruePositives+m.FalsePositives > 0 {
			reposWithTriage++
			precisions = append(precisions, m.Precision)
			noiseRates = append(noiseRates, m.NoiseRate)
		}

		for tool, count := range m.ToolFindings {
			s.ToolComparison[tool] += count
		}
	}

	if s.ReposScanned > 0 {
		s.AvgScanTime = totalScanTime / time.Duration(s.ReposScanned)
	}
	s.CacheWarmSpeedup = avg(speedups)
	s.AvgRecall = avg(recalls)
	s.AvgFrameworkRecall = avg(frameworkRecalls)
	s.AvgPrecision = avg(precisions)
	s.AvgNoiseRate = avg(noiseRates)

	// If no triage was recorded, all findings are unknown/unreviewed.
	if s.ConfirmedTruePos+s.FalsePositives == 0 && s.UnknownUnreviewed == 0 {
		s.UnknownUnreviewed = s.TotalFindings
	}

	if reposWithRecall == 0 {
		s.Limitations = append(s.Limitations, "Recall not computed: no repos declared expected_findings.")
	}
	if reposWithFrameworkRecall == 0 {
		s.Limitations = append(s.Limitations, "Framework recall not computed: no repos declared expected_framework_findings.")
	}
	if reposWithTriage == 0 {
		s.Limitations = append(s.Limitations, "Precision/noise not computed: no triaged findings. Run `benchmark triage` or supply a review file.")
	}
	return s
}

func avg(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	var sum float64
	for _, x := range xs {
		sum += x
	}
	return sum / float64(len(xs))
}

// ComputePrecision sets precision and noise rate on a Metrics struct from its
// triaged true/false positive counts. Unknown findings are excluded from the
// precision denominator (precision = TP / (TP + FP)).
func ComputePrecision(m *Metrics) {
	reviewed := m.TruePositives + m.FalsePositives
	if reviewed > 0 {
		m.Precision = float64(m.TruePositives) / float64(reviewed)
		m.NoiseRate = float64(m.FalsePositives) / float64(reviewed)
	}
	if m.TotalFindings > 0 {
		m.Unknown = m.TotalFindings - m.TruePositives - m.FalsePositives
	}
}
