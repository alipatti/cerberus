library(tidyverse)

batch_size <-
    list.files("benches/results/token_creation") %>%
    as.numeric() %>%
    sort()

total_time <- c()

for (i in seq_along(batch_size)) {
    path <- glue::glue(
        "./benches/results/token_creation/",
        "{batch_size[i]}/new/estimates.json"
    )
    total_time[i] <- jsonlite::read_json(path)$mean$point_estimate
}

results <- tibble(batch_size, total_time_ms = total_time / 1e6) %>%
    mutate(per_token_time_ms = total_time_ms / batch_size)

plot <- ggplot(results, aes(x = batch_size, y = total_time_ms)) +
    geom_line(color = "gray") +
    geom_point() # + coord_trans(x = "log", y = "log")
