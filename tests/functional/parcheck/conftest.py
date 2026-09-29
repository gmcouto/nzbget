import os
import shutil
import pytest


@pytest.fixture(scope='session', autouse=True)
def prepare_testdata(request, check_config, generate_nzbs):
	print('Preparing test data for "parcheck"')

	nserv_datadir = request.config.getini('nserv_datadir')

	if not os.path.exists(nserv_datadir):
		print('Creating nserv datadir')
		os.makedirs(nserv_datadir)

	nzbget_srcdir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

	testdata_dir = nzbget_srcdir + '/tests/testdata'
	if not os.path.exists(nserv_datadir + '/parchecker'):
		shutil.copytree(testdata_dir +'/parchecker', nserv_datadir + '/parchecker')
	if not os.path.exists(nserv_datadir + '/parchecker2'):
		shutil.copytree(testdata_dir +'/parchecker2', nserv_datadir + '/parchecker2')

	generate_nzbs(['parchecker', 'parchecker2'], 3000)
