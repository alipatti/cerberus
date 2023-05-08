library(tidyverse)

benchmark_parameters <-
    list.files("benches/results/token_creation")

total_time <- c() # in ms

for (i in seq_along(benchmark_parameters)) {
    path <- glue::glue(
        "./benches/results/token_creation/",
        "{benchmark_parameters[i]}/new/estimates.json"
    )
    total_time[i] <- jsonlite::read_json(path)$mean$point_estimate / 1e6
}

results <-
    tibble(benchmark_parameters, total_time) %>%
    separate_wider_delim(
        benchmark_parameters,
        delim = "-",
        names = c("n", "t", "batch_size"),
    ) %>%
    mutate(across(c(n, t), as.factor)) %>%
    mutate(across(batch_size, as.integer))

# per-token creation time
results %>%
    group_by(n) %>%
    transmute(per_token_time = total_time / batch_size) %>%
    summarise(mean(per_token_time))


# -- save plot --

tikzDevice::tikz(
    file = "benchmark-plot.tex",
    standAlone = F,
    width = 3,
    height = 3
)

# creation time as function of batch size
plot <- ggplot(results, aes(x = batch_size, y = total_time, color = n)) +
    geom_line() +
    geom_point() +
    labs(x = "Batch size", y = "Total runtime (ms)", color = "$n$") +
    theme(legend.position = "top")
print(plot)

dev.off()
