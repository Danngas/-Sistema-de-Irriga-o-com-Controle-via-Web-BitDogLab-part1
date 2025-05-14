#include <matrizled.c>
#include "pico/stdlib.h"
#include <time.h>
// AQUI ESTA O MAPEAMENTO DE TODOS OS NUMEROS DE 0 A 9
// por padrao foi definido a exibicao dos nuemros na cor VERMELHA

#define intensidade 1

void printNum()
{
    npWrite();
    // sleep_ms(2000);
    npClear();
}

// Definindo as cores RGB
#define VERDE {0, 1, 0}    // Verde
#define VERMELHO {1, 0, 0} // Vermelho
#define PRETO {0, 0, 0}    // Apagado (Preto)

// Matriz 5x5 de LEDs, inicializada com todos desligados
int OFF[5][5][3] = {
    {{0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}},
    {{0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}},
    {{0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}},
    {{0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}},
    {{0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}}};

// Função para atualizar os setores de acordo com o comando



void DesligaMatriz()
{
    desenhaSprite(OFF, intensidade);
    printNum();
}

// Função para atualizar os setores de acordo com o comando
void Atualizar_Setor(int setor, int comando) {
    // Comando 1 para ligar o setor, 0 para desligar
    int cor_ligado[3] = {0, 128, 0};    // Verde para ligado
    int cor_desligado[3] = {128, 0, 0}; // Vermelho para desligado

    // Define os intervalos de cada setor na matriz
    switch (setor) {
        case 1:
            for (int i = 0; i < 2; i++) {
                for (int j = 0; j < 2; j++) {
                    if (comando == 1) {
                        OFF[i][j][0] = cor_ligado[0];
                        OFF[i][j][1] = cor_ligado[1];
                        OFF[i][j][2] = cor_ligado[2];
                    } else {
                        OFF[i][j][0] = cor_desligado[0];
                        OFF[i][j][1] = cor_desligado[1];
                        OFF[i][j][2] = cor_desligado[2];
                    }
                }
            }
            break;
        case 2:
            for (int i = 0; i < 2; i++) {
                for (int j = 3; j < 5; j++) {
                    if (comando == 1) {
                        OFF[i][j][0] = cor_ligado[0];
                        OFF[i][j][1] = cor_ligado[1];
                        OFF[i][j][2] = cor_ligado[2];
                    } else {
                        OFF[i][j][0] = cor_desligado[0];
                        OFF[i][j][1] = cor_desligado[1];
                        OFF[i][j][2] = cor_desligado[2];
                    }
                }
            }
            break;
        case 3:
            for (int i = 3; i < 5; i++) {
                for (int j = 0; j < 2; j++) {
                    if (comando == 1) {
                        OFF[i][j][0] = cor_ligado[0];
                        OFF[i][j][1] = cor_ligado[1];
                        OFF[i][j][2] = cor_ligado[2];
                    } else {
                        OFF[i][j][0] = cor_desligado[0];
                        OFF[i][j][1] = cor_desligado[1];
                        OFF[i][j][2] = cor_desligado[2];
                    }
                }
            }
            break;
        case 4:
            for (int i = 3; i < 5; i++) {
                for (int j = 3; j < 5; j++) {
                    if (comando == 1) {
                        OFF[i][j][0] = cor_ligado[0];
                        OFF[i][j][1] = cor_ligado[1];
                        OFF[i][j][2] = cor_ligado[2];
                    } else {
                        OFF[i][j][0] = cor_desligado[0];
                        OFF[i][j][1] = cor_desligado[1];
                        OFF[i][j][2] = cor_desligado[2];
                    }
                }
            }
            break;
        default:
            break;
    }

    // Após atualizar os LEDs, você pode chamar a função para atualizar a matriz na interface ou hardware.
    desenhaSprite(OFF, 1);
    printNum();
    
}
