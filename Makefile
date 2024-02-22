.PHONY: create-image
create-image:
	@$(MAKE) -C docker pull

.PHONY: setup-env
setup-env:
	@$(MAKE) -C docker down up