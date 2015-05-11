library(httr)
library(jsonlite)
library(dplyr)
library(scales)
library(ggplot2)
library(pbapply)
library(data.table)
library(ipv4heatmap) # devtools::install_github("hrbrmstr/ipv4heatmap")

# Read in data ------------------------------------------------------------

source_url <- "http://jordan-wright.github.io/downloads/elastichoney_logs.json.gz"
resp <- try(GET(source_url, write_disk("data/elastichoney_logs.json.gz")), silent=TRUE)
elas <- fromJSON("data/elastichoney_logs.json.gz")

# Clean it up a bit and ignore geoip data ---------------------------------

elas %>%
  select(major, os_name, name, form, source, os, timestamp=`@timestamp`, method,
         device, honeypot, type, minor, os_major, os_minor, patch) %>%
  mutate(timestamp=as.POSIXct(timestamp, format="%Y-%m-%dT%H:%M:%OS"),
         day=as.Date(timestamp),
         method=toupper(method)) -> elas

# Take a look at attacks vs recons ----------------------------------------

gg <- ggplot(count(elas, day, type), aes(x=day, y=n, group=type))
gg <- gg + geom_bar(stat="identity", aes(fill=type), position="stack")
gg <- gg + scale_y_continuous(expand=c(0,0), limits=c(NA, 700))
gg <- gg + scale_x_date(expand=c(0,0))
gg <- gg + scale_fill_manual(name="Type", values=c("#1b6555", "#f3bc33"))
gg <- gg + labs(x=NULL, y="# sources", title="Attacks/Recons per day")
gg <- gg + theme_bw()
gg <- gg + theme(panel.background=element_rect(fill="#96c44722"))
gg <- gg + theme(panel.border=element_blank())
gg <- gg + theme(panel.grid=element_blank())
gg


# Take a look at April 24 -------------------------------------------------

elas %>%
  filter(day==as.Date("2015-04-24")) %>%
  count(source) %>%
  arrange(desc(n))

# Take a look at contacts by request type ---------------------------------

gg <- ggplot(count(elas, method), aes(x=reorder(method, -n), y=n))
gg <- gg + geom_bar(stat="identity", fill="#1b6555", width=0.5)
gg <- gg + scale_x_discrete(expand=c(0,0))
gg <- gg + scale_y_continuous(expand=c(0,0))
gg <- gg + labs(x=NULL, y=NULL, title="Contacts by Request type")
gg <- gg + coord_flip()
gg <- gg + theme_bw()
gg <- gg + theme(panel.background=element_blank())
gg <- gg + theme(panel.border=element_blank())
gg <- gg + theme(panel.grid=element_blank())
gg <- gg + theme(axis.ticks.y=element_blank())
gg

# Take a look at contacts by os type --------------------------------------

gg <- ggplot(count(elas, os), aes(x=reorder(os, -n), y=n))
gg <- gg + geom_bar(stat="identity", fill="#1b6555", width=0.5)
gg <- gg + scale_x_discrete(expand=c(0,0))
gg <- gg + scale_y_continuous(expand=c(0,0))
gg <- gg + labs(x=NULL, y=NULL, title="Contacts by OS type")
gg <- gg + coord_flip()
gg <- gg + theme_bw()
gg <- gg + theme(panel.background=element_blank())
gg <- gg + theme(panel.border=element_blank())
gg <- gg + theme(panel.grid=element_blank())
gg <- gg + theme(axis.ticks.y=element_blank())
gg

# Top 30 attack IPs -------------------------------------------------------

elas %>%
  count(source) %>%
  mutate(pct=percent(n/nrow(elas))) %>%
  arrange(desc(n)) %>%
  head(30) %>%
  mutate(source=sprintf("%s (%s)", source, pct)) -> attack_src

gg <- ggplot(attack_src, aes(x=reorder(source, -n), y=n))
gg <- gg + geom_bar(stat="identity", fill="#1b6555", width=0.5)
gg <- gg + scale_x_discrete(expand=c(0,0))
gg <- gg + scale_y_continuous(expand=c(0,0))
gg <- gg + labs(x=NULL, y=NULL, title="Top 30 attackers")
gg <- gg + coord_flip()
gg <- gg + theme_bw()
gg <- gg + theme(panel.background=element_blank())
gg <- gg + theme(panel.border=element_blank())
gg <- gg + theme(panel.grid=element_blank())
gg <- gg + theme(axis.ticks.y=element_blank())
gg

# Take a look at Hilbert space --------------------------------------------

hm <- ipv4heatmap(elas$source)

china <- grep("^#", readLines("http://www.iwik.org/ipcountry/CN.cidr"), invert=TRUE, value=TRUE)
cidrs <- rbindlist(pbsapply(china, boundingBoxFromCIDR))
hm$gg +
 geom_rect(data=cidrs,
           aes(xmin=xmin, ymin=ymin, xmax=xmax, ymax=ymax),
           fill="white", alpha=0.1) -> ipgg
png("output/china.png", width=4096, height=4096)
print(ipgg)
dev.off()

png("output/china-small.png", width=600, height=600)
print(ipgg)
dev.off()







