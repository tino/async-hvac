test: version
	tox

version:
	cp version async_hvac/version

clean:
	rm -rf dist async_hvac.egg-info

distclean: clean
	rm -rf build async_hvac/version .tox

package: version
	python setup.py sdist

.PHONY: clean package publish test version
