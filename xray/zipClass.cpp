#include "zipClass.h"


zip_t* zip_manager::windows_open(const char* name, int flags) {
	zip_source_t* src;
	zip_t* za;
	zip_error_t error;

	zip_error_init(&error);
	/* create source from buffer */
	if ((src = zip_source_win32a_create(name, 0, -1, &error)) == NULL) {
		fprintf(stderr, "can't create source: %s\n", zip_error_strerror(&error));
		zip_error_fini(&error);
		return NULL;
	}

	/* open zip archive from source */
	if ((za = zip_open_from_source(src, flags, &error)) == NULL) {
		fprintf(stderr, "can't open zip from source: %s\n", zip_error_strerror(&error));
		zip_source_free(src);
		zip_error_fini(&error);
		return NULL;
	}
	zip_error_fini(&error);

	return za;
}



void zip_manager::Unzip_Password_ProtectedFile(LPSTR FilePath, LPSTR FileName, LPSTR Password, LPSTR OutPath)
{

	zip_t* archive = nullptr;
	zip_file_t* file_ptr = nullptr;
	zip_error_t* error = nullptr;
	zip_stat_t file_stats;
	HANDLE hNewFile;


	archive = windows_open(FilePath, 0);
	if (archive == nullptr)
	{
		Errors.push_back(ERROR_LIBZIP_WINOPEN);
		return;
	}
	

	zip_set_default_password(archive, Password);
	file_ptr = zip_fopen(archive, FileName, ZIP_FL_NOCASE);
	if (!file_ptr)
	{
		Errors.push_back(ERROR_LIBZIP_FOPEN);
		return;
	}
	

	int success = zip_stat(archive, FileName, ZIP_FL_NOCASE, &file_stats);
	if (success == -1) {
		Errors.push_back(ERROR_LIBZIP_ZSTAT);
		return;
	}
	
	if (!(file_stats.valid | ZIP_STAT_SIZE))
	{
		Errors.push_back(ERROR_LIBZIP_ZSTAT);
		return;
	}


	RAII::NewBuffer file_read_buf(file_stats.size);
	BYTE* file_buf = file_read_buf.Get();

	zip_fread(file_ptr, file_buf, file_stats.size);

	hNewFile = CreateFileA(OutPath, GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (!hNewFile)
	{
		Errors.push_back(GetLastError());
		return;
	}
	if (!WriteFile(hNewFile, file_buf, file_stats.size, 0, 0))
	{
		Errors.push_back(GetLastError());
		return;
	}


	if (file_ptr)
	{
		zip_fclose(file_ptr);
	}
	
}