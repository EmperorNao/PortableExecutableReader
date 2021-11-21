#include "Headers.h"


int main(int argc, char* argv[]) {
	
	if (argc < 2) {

		printf("Missing argument: file\n");
		return -1;

	}

	std::string filename = argv[1];
	auto sections_info = parse_args(argc, argv);
	return parse_executable(filename, sections_info);


}