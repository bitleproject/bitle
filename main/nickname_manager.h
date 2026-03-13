#pragma once

#include <stddef.h>
#include "esp_err.h"

esp_err_t nickname_init(char *out_nickname, size_t max_len);
esp_err_t nickname_set(const char *nickname);
esp_err_t nickname_regenerate(char *out_nickname, size_t max_len);
