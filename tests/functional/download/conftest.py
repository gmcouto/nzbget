import os
import shutil
import subprocess
import pytest


def pytest_addoption(parser):
	parser.addini('sample_medium', 'size of meidum nzb (megabytes)', default=192)
	parser.addini('sample_large', 'size of large nzb (megabytes)', default=1024)


@pytest.fixture(scope='session', autouse=True)
def prepare_testdata(request, check_config, generate_nzbs):
	print('Preparing test data for "download"')

	nserv_datadir = request.config.getini('nserv_datadir')
	sevenzip_bin = request.config.getini('sevenzip_bin')

	if not os.path.exists(nserv_datadir):
		print('Creating nserv datadir')
		os.makedirs(nserv_datadir)

	sizemb = int(request.config.getini('sample_medium'))
	if not sample_matches(nserv_datadir + '/medium', sizemb, 50):
		create_test_file(nserv_datadir + '/medium', sevenzip_bin, sizemb, 50)

	sizemb = int(request.config.getini('sample_large'))
	if not sample_matches(nserv_datadir + '/large', sizemb, 50):
		create_test_file(nserv_datadir + '/large', sevenzip_bin, sizemb, 50)

	nzbget_srcdir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
	if not os.path.exists(nserv_datadir + '/small'):
		os.makedirs(nserv_datadir + '/small')
		shutil.copyfile(nzbget_srcdir +'/COPYING', nserv_datadir + '/small/small.dat')

	if not os.path.exists(nserv_datadir + '/small-obfuscated'):
		os.makedirs(nserv_datadir + '/small-obfuscated')
		shutil.copyfile(nzbget_srcdir +'/COPYING', nserv_datadir + '/small-obfuscated/fsdkhKHGuwuMNBKskd')

	generate_nzbs(['medium', 'large'], 500000)
	generate_nzbs(['small', 'small-obfuscated'], 3000)


def sample_matches(bigdir, sizemb, partmb):
	if not os.path.isdir(bigdir):
		return False

	parts = [os.path.join(bigdir, filename) for filename in os.listdir(bigdir) if '.7z.' in filename]
	expected_parts = (sizemb + partmb - 1) // partmb
	expected_bytes = sizemb * 1024 * 1024
	return len(parts) == expected_parts and sum(os.path.getsize(part) for part in parts) >= expected_bytes


def create_test_file(bigdir, sevenzip_bin, sizemb, partmb):
	print('Preparing test file (' + str(sizemb) + 'MB)')

	if os.path.exists(bigdir):
		shutil.rmtree(bigdir)
	os.makedirs(bigdir)

	f = open(bigdir + '/' + str(sizemb) + 'mb.dat', 'wb')
	for n in range(sizemb // partmb):
		print('Writing block %i from %i' % (n + 1, sizemb // partmb))
		f.write(os.urandom(partmb * 1024 * 1024))
	f.close()

	if 0 != subprocess.call([sevenzip_bin, 'a', bigdir + '/' + str(sizemb) + 'mb.7z', '-mx=0', '-v' + str(partmb) + 'm', bigdir + '/' + str(sizemb) + 'mb.dat']):
		pytest.exit('Test file generation failed')

	os.remove(bigdir + '/' + str(sizemb) + 'mb.dat')
