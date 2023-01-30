#pragma once
#include "nlohmann/json.hpp"


using namespace nlohmann;



static const json api_OK
{
	{"STATUS", "OK" },
	{"Command", ""}
};

static const json api_ERROR
{
	{"STATUS", "ERROR"}
};