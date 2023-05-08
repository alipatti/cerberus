library(tidyverse)

####################
## TOKEN CREATION ##
####################

benchmark_parameters <-
    list.files("../benches/results/token_creation")

total_time <- c() # in ms

for (i in seq_along(benchmark_parameters)) {
    path <- glue::glue(
        "../benches/results/token_creation/",
        "{benchmark_parameters[i]}/new/estimates.json"
    )
    total_time[i] <- jsonlite::read_json(path)$mean$point_estimate / 1e6
}

token_creation_results <-
    tibble(benchmark_parameters, total_time) %>%
    separate_wider_delim(
        benchmark_parameters,
        delim = "-",
        names = c("n", "t", "batch_size"),
    ) %>%
    mutate(across(c(n, t), as.factor)) %>%
    mutate(across(batch_size, as.integer))

# creation time as function of batch size

create_plot <- function() {
    plot <- ggplot(
        token_creation_results,
        aes(x = batch_size, y = total_time, color = n)
    ) +
        geom_line() +
        geom_point() +
        labs(x = "Batch size", y = "Total runtime (ms)", color = "$n$") +
        theme(
            legend.position = c(.35, .88),
            legend.direction = "horizontal",
            legend.background = element_blank()
        )

    tikzDevice::tikz(
        file = "benchmark-plot.tex",
        standAlone = F,
        width = 3,
        height = 2.2
    )
    print(plot)
    dev.off()
}

#######################
## MESSAGE REPORTING ##
#######################

benchmark_parameters <-
    list.files("../benches/results/message_reporting")

per_report <- c() # in ms

for (i in seq_along(benchmark_parameters)) {
    path <- glue::glue(
        "../benches/results/message_reporting/",
        "{benchmark_parameters[i]}/new/estimates.json"
    )
    per_report[i] <- jsonlite::read_json(path)$mean$point_estimate / 1e6
}

create_table <- function() {
    # per-token creation time
    token_creation_results %>%
        group_by(n) %>%
        transmute(per_token_time = total_time / batch_size) %>%
        summarise(per_token = mean(per_token_time)) %>%
        mutate(per_report = per_report)
}
