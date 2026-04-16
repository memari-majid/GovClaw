# Research-level Makefile. Lives under research/ so it never collides with
# the upstream top-level Makefile.

PAPER      := paper/paper.md
BUILD_DIR  := build
PDF        := $(BUILD_DIR)/paper.pdf
HTML       := $(BUILD_DIR)/paper.html
BIB        := paper/references.bib

.PHONY: all paper pdf html experiments sync clean help

help:
	@echo "ClawKeeper research targets:"
	@echo "  make paper        Render the manuscript (PDF if TeX available, else HTML)"
	@echo "  make pdf          Force PDF render (requires pandoc + a TeX engine)"
	@echo "  make html         HTML render of the manuscript"
	@echo "  make experiments  Run every experiment under experiments/"
	@echo "  make sync         Sync latest upstream/main into this fork"
	@echo "  make clean        Remove $(BUILD_DIR)/ and transient artifacts"

paper: | $(BUILD_DIR)
	@if command -v pandoc >/dev/null && command -v pdflatex >/dev/null; then \
		$(MAKE) pdf ; \
	elif command -v pandoc >/dev/null; then \
		echo "pandoc found but no TeX engine; falling back to HTML" ; \
		$(MAKE) html ; \
	else \
		echo "pandoc not installed — open paper/paper.md directly, or install pandoc to render." ; \
		exit 0 ; \
	fi

pdf: $(PDF)
$(PDF): $(PAPER) $(BIB) | $(BUILD_DIR)
	pandoc $(PAPER) --citeproc --bibliography=$(BIB) \
		--number-sections --toc -o $(PDF)
	@echo "wrote $(PDF)"

html: $(HTML)
$(HTML): $(PAPER) $(BIB) | $(BUILD_DIR)
	pandoc $(PAPER) --citeproc --bibliography=$(BIB) \
		--number-sections --toc --standalone -o $(HTML)
	@echo "wrote $(HTML)"

experiments:
	@bash experiments/run-all.sh

sync:
	@bash tools/sync-upstream.sh

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)
