#pragma once

float** matrix_alloc(int rows, int cols);

float** matrix_transpose(float** matrix, int rows, int cols);

void matrix_free(float** matrix, int rows);