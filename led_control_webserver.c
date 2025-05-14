#include <stdio.h>  // Biblioteca padrão para entrada e saída
#include <string.h> // Biblioteca manipular strings
#include <stdlib.h> // funções para realizar várias operações, incluindo alocação de memória dinâmica (malloc)

#include "pico/stdlib.h"     // Biblioteca da Raspberry Pi Pico para funções padrão (GPIO, temporização, etc.)
#include "hardware/adc.h"    // Biblioteca da Raspberry Pi Pico para manipulação do conversor ADC
#include "pico/cyw43_arch.h" // Biblioteca para arquitetura Wi-Fi da Pico com CYW43

#include "lwip/pbuf.h"  // Lightweight IP stack - manipulação de buffers de pacotes de rede
#include "lwip/tcp.h"   // Lightweight IP stack - fornece funções e estruturas para trabalhar com o protocolo TCP
#include "lwip/netif.h" // Lightweight IP stack - fornece funções e estruturas para trabalhar com interfaces de rede (netif)
// Biblioteca com desenhos personalizados para a matriz de led
#include "numeros.h"
// MODO BOOTSEL (reset via botão B)
#include "pico/bootrom.h" // Biblioteca para reinicialização via USB
#include "hardware/timer.h"
#include "hardware/pwm.h"
#include "hardware/adc.h"
#include "hardware/i2c.h"
#include "lib/ssd1306.h"
#include "lib/font.h"
#include <math.h>

// ----------------------------- DEFINIÇÕES DE PINOS -----------------------------
#define MATRIZ_LED_PIN 7 // Pino conectado à matriz de LEDs WS2812

// Credenciais WIFI - Tome cuidado se publicar no github!
#define WIFI_SSID "Tesla"
#define WIFI_PASSWORD "123456788"

// Definição dos pinos dos LEDs
// #define LED_PIN CYW43_WL_GPIO_LED_PIN // GPIO do CI CYW43
#define LED_BLUE_PIN 12  // GPIO12 - LED azul
#define LED_GREEN_PIN 11 // GPIO11 - LED verde
#define LED_RED_PIN 13   // GPIO13 - LED vermelho
#define BUZZER_PIN 10    // Pino do buzzer

// Definições dos pinos para os botões
#define BUTTON_A_GPIO 5 // Pino do botão A
#define BUTTON_B_GPIO 6 // Pino do botão B

int setor_1comando = 0;
int setor_2comando = 0;
int setor_3comando = 0;
int setor_4comando = 0;

int setor_atual = 1;

#define I2C_PORT i2c1
#define I2C_SDA 14
#define I2C_SCL 15
#define endereco 0x3C

struct repeating_timer meu_timer;
bool alarme_ativo = false;

bool botao_a_press = false;

// Defina as variáveis para os estados
bool wifi_connected = true; // Exemplo: WiFi está conectado
bool automatic_mode = true; // Exemplo: Modo automático
bool sector1_on = true;     // Exemplo: Setor 1 ligado
bool sector2_on = false;    // Exemplo: Setor 2 desligado
bool sector3_on = true;     // Exemplo: Setor 3 ligado
bool sector4_on = false;    // Exemplo: Setor 4 desligado

#define ATRASO_CONTADOR 3000
// Definição do modo (automático ou manual)
char *modo_atual = "Manual";

char setores_ativos[50];

// Tempo de debounce em milissegundos
#define DEBOUNCE_DELAY_MS 200

// Variáveis para controlar o estado do debounce
uint32_t last_interrupt_time_a = 0; // Tempo da última interrupção do botão A
uint32_t last_interrupt_time_b = 0; // Tempo da última interrupção do botão B

// Flag para controlar o estado do botão A
// strcpy(setores_ativos, "Nenhum");

// Inicializar os Pinos GPIO para acionamento dos LEDs da BitDogLab
void gpio_led_bitdog(void);
void iniciarModoAutomatico();
void pararModoAutomatico();
void iniciar_pwm_buzzer(uint freq_hz);
void parar_pwm_buzzer();
void atualizarSetoresAtivos();
void toggle_mode();
void update_display(ssd1306_t *ssd);

// Função de callback ao aceitar conexões TCP
static err_t tcp_server_accept(void *arg, struct tcp_pcb *newpcb, err_t err);

// Função de callback para processar requisições HTTP
static err_t tcp_server_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);

// Leitura da temperatura interna
float temp_read(void);

// Tratamento do request do usuário
void user_request(char **request);

// comando de acordo com o botao aiconado na inetrface
void comando(void);

// Função principal

bool precisaAtualizar = false;

bool repeating_timer_callback(struct repeating_timer *t)
{
    if (strcmp(modo_atual, "Automático") == 0)
    {

        precisaAtualizar = true;

        setor_atual++;

        if (setor_atual > 4)
            setor_atual = 1;
        printf("Modo automático ativo - setor atual: %d\n", setor_atual);
    }
    return true;
}

// Handler de interrupção para os botões
void gpio_irq_handler(uint gpio, uint32_t events)
{
    uint32_t current_time = to_ms_since_boot(get_absolute_time()); // Tempo atual em milissegundos

    if (gpio == BUTTON_A_GPIO)
    {
        // Verifica se o tempo de debounce passou
        if (current_time - last_interrupt_time_a > DEBOUNCE_DELAY_MS)
        {
            last_interrupt_time_a = current_time; // Atualiza o tempo da última interrupção
            botao_a_press = !botao_a_press;       // Alterna o estado do botão A
            printf("Botão A pressionado: %s\n", botao_a_press ? "Ativado" : "Desativado");
        }
    }
    else if (gpio == BUTTON_B_GPIO)
    {
        // Verifica se o tempo de debounce passou
        if (current_time - last_interrupt_time_b > DEBOUNCE_DELAY_MS)
        {
            last_interrupt_time_b = current_time; // Atualiza o tempo da última interrupção
            reset_usb_boot(0, 0);                 // Reinicia o Pico no modo BOOTSEL
        }
    }
}

int main()
{
    // Inicializa todos os tipos de bibliotecas stdio padrão presentes que estão ligados ao binário.
    stdio_init_all();
    npInit(MATRIZ_LED_PIN); // Inicializa a matriz de LEDs WS2812

    // Configuração do botão B para modo BOOTSEL
    gpio_init(BUTTON_B_GPIO);
    gpio_set_dir(BUTTON_B_GPIO, GPIO_IN);
    gpio_pull_up(BUTTON_B_GPIO);
    gpio_set_irq_enabled_with_callback(BUTTON_B_GPIO, GPIO_IRQ_EDGE_FALL, true, &gpio_irq_handler);

    gpio_init(BUTTON_A_GPIO);
    gpio_set_dir(BUTTON_A_GPIO, GPIO_IN);
    gpio_pull_up(BUTTON_A_GPIO);
    gpio_set_irq_enabled_with_callback(BUTTON_A_GPIO, GPIO_IRQ_EDGE_FALL, true, &gpio_irq_handler);

    DesligaMatriz();
    Atualizar_Setor(1, setor_1comando);
    Atualizar_Setor(2, setor_2comando);
    Atualizar_Setor(3, setor_3comando);
    Atualizar_Setor(4, setor_4comando);

    strcpy(setores_ativos, "Nenhum");

    // Inicializa I2C e Display
    i2c_init(I2C_PORT, 400 * 1000);
    gpio_set_function(I2C_SDA, GPIO_FUNC_I2C);
    gpio_set_function(I2C_SCL, GPIO_FUNC_I2C);
    gpio_pull_up(I2C_SDA);
    gpio_pull_up(I2C_SCL);

    ssd1306_t ssd;
    ssd1306_init(&ssd, WIDTH, HEIGHT, false, endereco, I2C_PORT);
    ssd1306_config(&ssd);
    ssd1306_send_data(&ssd);
    ssd1306_fill(&ssd, false);
    ssd1306_send_data(&ssd);

    bool cor = true;

    update_display(&ssd);
    // Inicializar os Pinos GPIO para acionamento dos LEDs da BitDogLab
    gpio_led_bitdog();

    // Inicializa a arquitetura do cyw43

    while (cyw43_arch_init())
    {
        printf("Falha ao inicializar Wi-Fi\n");
        sleep_ms(100);
        return -1;
    }

    // GPIO do CI CYW43 em nível baixo
    cyw43_arch_gpio_put(LED_PIN, 0);

    // Ativa o Wi-Fi no modo Station, de modo a que possam ser feitas ligações a outros pontos de acesso Wi-Fi.
    cyw43_arch_enable_sta_mode();

    // Conectar à rede WiFI - fazer um loop até que esteja conectado
    printf("Conectando ao Wi-Fi...\n");
    while (cyw43_arch_wifi_connect_timeout_ms(WIFI_SSID, WIFI_PASSWORD, CYW43_AUTH_WPA2_AES_PSK, 20000))
    {

        printf("Falha ao conectar ao Wi-Fi\n");
        sleep_ms(100);
        return -1;
    }
    printf("Conectado ao Wi-Fi\n");

    // Caso seja a interface de rede padrão - imprimir o IP do dispositivo.
    if (netif_default)
    {
        printf("IP do dispositivo: %s\n", ipaddr_ntoa(&netif_default->ip_addr));
    }

    // Configura o servidor TCP - cria novos PCBs TCP. É o primeiro passo para estabelecer uma conexão TCP.
    struct tcp_pcb *server = tcp_new();
    if (!server)
    {
        printf("Falha ao criar servidor TCP\n");
        return -1;
    }

    // vincula um PCB (Protocol Control Block) TCP a um endereço IP e porta específicos.
    if (tcp_bind(server, IP_ADDR_ANY, 80) != ERR_OK)
    {
        printf("Falha ao associar servidor TCP à porta 80\n");
        return -1;
    }

    // Coloca um PCB (Protocol Control Block) TCP em modo de escuta, permitindo que ele aceite conexões de entrada.
    server = tcp_listen(server);

    // Define uma função de callback para aceitar conexões TCP de entrada. É um passo importante na configuração de servidores TCP.
    tcp_accept(server, tcp_server_accept);
    printf("Servidor ouvindo na porta 80\n");

    // Inicializa o conversor ADC
    adc_init();
    adc_set_temp_sensor_enabled(true);

    while (true)
    {

        update_display(&ssd);
        if (precisaAtualizar)
        {
            Atualizar_Setor(1, 0);
            Atualizar_Setor(2, 0);
            Atualizar_Setor(3, 0);
            Atualizar_Setor(4, 0);
            setor_1comando = 0;
            setor_2comando = 0;
            setor_3comando = 0;
            setor_4comando = 0;
            switch (setor_atual)
            {
            case 1:
                setor_1comando = 1;
                break;
            case 2:
                setor_2comando = 1;
                break;
            case 3:
                setor_3comando = 1;
                break;
            case 4:
                setor_4comando = 1;
                break;

            default:
                break;
            }
            Atualizar_Setor(setor_atual, 1);
            precisaAtualizar = false;
            atualizarSetoresAtivos();
            char request2[512];
            strcpy(request2, "GET /Setor_1 HTTP/1.1");
            char *ptr = request2; // ponteiro simples para a string
            user_request(&ptr);   // &ptr é do tipo char**

            // location.reload();
            iniciar_pwm_buzzer(500); // Beep de 500Hz
            sleep_ms(50);
            parar_pwm_buzzer();
        }

        if (botao_a_press)
        {
            toggle_mode();
            botao_a_press = !botao_a_press;
        }

        /*
         * Efetuar o processamento exigido pelo cyw43_driver ou pela stack TCP/IP.
         * Este método deve ser chamado periodicamente a partir do ciclo principal
         * quando se utiliza um estilo de sondagem pico_cyw43_arch
         */
        cyw43_arch_poll(); // Necessário para manter o Wi-Fi ativo
        sleep_ms(100);     // Reduz o uso da CPU

        // Linha das cores

        // Atualiza o display

        /*
                // Setor 2
                ssd1306_rect(&ssd, 32, 52, 32, 32, true, false);
                if (sector2_on)
                {
                    ssd1306_fill(&ssd, true); // Preenche se o setor estiver ligado
                }
                ssd1306_draw_string(&ssd, "Setor 2", 34 + borda, 52 + borda);

                // Setor 3
                ssd1306_rect(&ssd, 64, 52, 32, 32, true, false);
                if (sector3_on)
                {
                    ssd1306_fill(&ssd, true); // Preenche se o setor estiver ligado
                }
                ssd1306_draw_string(&ssd, "Setor 3", 66 + borda, 52 + borda);

                // Setor 4
                ssd1306_rect(&ssd, 96, 52, 32, 32, true, false);
                if (sector4_on)
                {
                    ssd1306_fill(&ssd, true); // Preenche se o setor estiver ligado
                }
                ssd1306_draw_string(&ssd, "Setor 4", 98 + borda, 52 + borda);

                // Enviar os dados para o display*/
    }

    // Desligar a arquitetura CYW43.
    cyw43_arch_deinit();
    return 0;
}

// -------------------------------------- Funções ---------------------------------

// Inicializar os Pinos GPIO para acionamento dos LEDs da BitDogLab
void gpio_led_bitdog(void)
{
    // Configuração dos LEDs como saída
    gpio_init(LED_BLUE_PIN);
    gpio_set_dir(LED_BLUE_PIN, GPIO_OUT);
    gpio_put(LED_BLUE_PIN, false);

    gpio_init(LED_GREEN_PIN);
    gpio_set_dir(LED_GREEN_PIN, GPIO_OUT);
    gpio_put(LED_GREEN_PIN, false);

    gpio_init(LED_RED_PIN);
    gpio_set_dir(LED_RED_PIN, GPIO_OUT);
    gpio_put(LED_RED_PIN, false);
}

// Função de callback ao aceitar conexões TCP
static err_t tcp_server_accept(void *arg, struct tcp_pcb *newpcb, err_t err)
{
    tcp_recv(newpcb, tcp_server_recv);
    return ERR_OK;
}

// Função para alternar o modo entre "Automático" e "Manual"
void toggle_mode(void)
{
    if (strcmp(modo_atual, "Automático") == 0)
    {
        modo_atual = "Manual";
        pararModoAutomatico();
    }
    else
    {
        Atualizar_Setor(1, 1);
        Atualizar_Setor(2, 0);
        Atualizar_Setor(3, 0);
        Atualizar_Setor(4, 0);
        setor_2comando = 0;
        setor_3comando = 0;
        setor_4comando = 0;
        setor_atual = 1;
        modo_atual = "Automático";
        setor_1comando = 1;
        iniciarModoAutomatico();
        atualizarSetoresAtivos();
        iniciar_pwm_buzzer(500); // Beep de 500Hz
        sleep_ms(50);
        parar_pwm_buzzer();
        // modo_automatico();
    }
}

void user_request(char **request)
{

    if (strcmp(modo_atual, "Manual") == 0)
    {

        if (strstr(*request, "GET /Setor_1") != NULL)
        {

            setor_1comando = !setor_1comando;
            Atualizar_Setor(1, setor_1comando);
            atualizarSetoresAtivos();

            iniciar_pwm_buzzer(100); // Beep de 500Hz
            sleep_ms(100);
            parar_pwm_buzzer();
        }
        else if (strstr(*request, "GET /Setor_2") != NULL)
        {
            setor_2comando = !setor_2comando;
            Atualizar_Setor(2, setor_2comando);
            atualizarSetoresAtivos();

            iniciar_pwm_buzzer(100); // Beep de 500Hz
            sleep_ms(100);
            parar_pwm_buzzer();
        }
        else if (strstr(*request, "GET /Setor_3") != NULL)
        {
            setor_3comando = !setor_3comando;
            Atualizar_Setor(3, setor_3comando);
            atualizarSetoresAtivos();
            iniciar_pwm_buzzer(100); // Beep de 500Hz
            sleep_ms(100);
            parar_pwm_buzzer();
        }
        else if (strstr(*request, "GET /Setor_4") != NULL)
        {
            setor_4comando = !setor_4comando;
            Atualizar_Setor(4, setor_4comando);
            atualizarSetoresAtivos();
            iniciar_pwm_buzzer(100); // Beep de 500Hz
            sleep_ms(100);
            parar_pwm_buzzer();
        }
    }

    if (strstr(*request, "GET /toggle_mode") != NULL)
    {
        toggle_mode(); // Alterna o modo
    }
};

// Leitura da temperatura interna
float temp_read(void)
{
    adc_select_input(4);
    uint16_t raw_value = adc_read();
    const float conversion_factor = 3.3f / (1 << 12);
    float temperature = 27.0f - ((raw_value * conversion_factor) - 0.706f) / 0.001721f;
    return temperature;
}

// Função de callback para processar requisições HTTP
static err_t tcp_server_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
    if (!p)
    {
        tcp_close(tpcb);
        tcp_recv(tpcb, NULL);
        return ERR_OK;
    }

    // Alocação do request na memória dinámica
    char *request = (char *)malloc(p->len + 1);
    memcpy(request, p->payload, p->len);
    request[p->len] = '\0';

    printf("Request: %s\n", request);

    // Tratamento de request - Controle dos LEDs
    user_request(&request);

    // Leitura da temperatura interna
    float temperature = temp_read();

    // Cria a resposta HTML
    char html[1024];

    snprintf(html, sizeof(html),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: text/html; charset=UTF-8\r\n"
             "\r\n"
             "<!DOCTYPE html>\n"
             "<html>\n"
             "<head>\n"
             "<title>Embarcatech - LED Control</title>\n"
             "<meta charset=\"UTF-8\">\n" // Adicionando o meta tag para UTF-8
             "<style>\n"
             "body { font-family: Arial, sans-serif; text-align: center; margin-top: 50px; background-color: #f4f7f6; color: #333; }\n"
             "h1 { font-size: 48px; margin-bottom: 30px; color: #4CAF50; }\n"
             "button { background-color: #4CAF50; font-size: 24px; margin: 10px; padding: 10px 20px; border-radius: 10px; }\n"
             ".button-container { display: flex; justify-content: center; gap: 20px; margin-top: 30px; }\n"
             "</style>\n"
             "</head>\n"
             "<body>\n"

             // Título da página
             "<h1>Controle de LED</h1>\n"

             // Exibe o modo atual (Automático ou Manual)
             "<p class=\"mode\">Modo Atual: %s</p>\n"

             // Exibe os setores ativos
             "<p class=\"Ligado\">Setores Ativos: %s</p>\n"

             // Botão para alternar o modo
             "<form action=\"./toggle_mode\">\n"
             "<button>Alternar Modo</button>\n"
             "</form>\n"

             // Layout para os botões de controle de LED
             "<div class=\"button-container\">\n"
             "<form action=\"./Setor_1\"><button>Setor 1</button></form>\n"
             "<form action=\"./Setor_2\"><button>Setor 2</button></form>\n"
             "<form action=\"./Setor_3\"><button>Setor 3</button></form>\n"
             "<form action=\"./Setor_4\"><button>Setor 4</button></form>\n"
             "</div>\n"

             "</body>\n"
             "</html>\n",
             modo_atual, setores_ativos // Exibe o modo atual e os setores ativos
    );

    // Escreve dados para envio (mas não os envia imediatamente).
    tcp_write(tpcb, html, strlen(html), TCP_WRITE_FLAG_COPY);

    // Envia a mensagem
    tcp_output(tpcb);

    // libera memória alocada dinamicamente
    free(request);

    // libera um buffer de pacote (pbuf) que foi alocado anteriormente
    pbuf_free(p);

    return ERR_OK;
}

void iniciarModoAutomatico()
{
    strcpy(modo_atual, "Automático");
    setor_atual = 1; // Resetar para o primeiro setor se quiser
    if (!alarme_ativo)
    {
        add_repeating_timer_ms(10000, repeating_timer_callback, NULL, &meu_timer);
        alarme_ativo = true;
        printf("Modo automático ativado\n");
    }
}

void pararModoAutomatico()
{
    strcpy(modo_atual, "Manual");
    if (alarme_ativo)
    {
        cancel_repeating_timer(&meu_timer);
        alarme_ativo = false;
        printf("Modo automático desativado\n");
    }
}

void iniciar_pwm_buzzer(uint freq_hz)
{
    gpio_set_function(BUZZER_PIN, GPIO_FUNC_PWM);
    uint slice = pwm_gpio_to_slice_num(BUZZER_PIN);
    uint clock = 125000000; // Clock padrão de 125 MHz
    uint divider = 4;       // Divisor de clock
    uint top = clock / (divider * freq_hz);

    pwm_set_clkdiv(slice, divider);
    pwm_set_wrap(slice, top);
    pwm_set_chan_level(slice, pwm_gpio_to_channel(BUZZER_PIN), top / 2); // Duty cycle de 50%
    pwm_set_enabled(slice, true);
}

// Função para parar o PWM do buzzer
void parar_pwm_buzzer()
{
    uint slice = pwm_gpio_to_slice_num(BUZZER_PIN);
    pwm_set_enabled(slice, false);
}

void atualizarSetoresAtivos()
{
    // Limpa a string
    setores_ativos[0] = '\0';

    // Verifica cada setor e adiciona o número à string se estiver ativo
    if (setor_1comando == 1)
    {

        strcat(setores_ativos, "1");
    }
    if (setor_2comando == 1)
    {

        if (strlen(setores_ativos) > 0)
            strcat(setores_ativos, " - ");
        strcat(setores_ativos, "2");
    }
    if (setor_3comando == 1)
    {

        if (strlen(setores_ativos) > 0)
            strcat(setores_ativos, " - ");
        strcat(setores_ativos, "3");
    }
    if (setor_4comando == 1)
    {

        if (strlen(setores_ativos) > 0)
            strcat(setores_ativos, " - ");
        strcat(setores_ativos, "4");
    }

    // Se nenhum setor estiver ativo
    if (strlen(setores_ativos) == 0)
    {

        strcpy(setores_ativos, "Nenhum");
    }

    printf("/n Setores  Ativos %s", setores_ativos);
}

// display=====================================================================================================

void update_display(ssd1306_t *ssd)
{
    // Limpar o display
    ssd1306_fill(ssd, false);

    // Borda para os textos
    int borda = 2;

    // Desenha os quadros
    ssd1306_rect(ssd, 0, 0, 128, 60, true, false); // Quadro principal

    ssd1306_draw_string(ssd, "WiFi: ", 8 + borda, 8 + borda);

    if (wifi_connected)
    {
        ssd1306_draw_string(ssd, "On", 50, 8 + borda);
    }
    else
    {
        // ssd1306_draw_string(ssd, " Off", 40, borda);
    }

    // ssd1306_draw_string(ssd, "Modo: ", 10 + borda, 5 + borda);
    if (automatic_mode)
    {
        // ssd1306_draw_string(ssd, "Automatico", 40, 36 + borda);
    }
    else
    {
        // ssd1306_draw_string(ssd, "Manual", 40, 36 + borda);
    }

    // Desenhando os 4 setores (em quadros)
    // Setor 1
    if (setor_1comando)
    {
        ssd1306_rect(ssd, 20, 20 + 20 + 20 + 10 + 20, 10, 10, true, true); // Amarelo (aceso)
    }
    else
    {
        ssd1306_rect(ssd, 20, 20 + 20 + 20 + 10 + 20, 10, 10, true, false); // Amarelo (aceso)
    }

    if (setor_2comando)
    {
        ssd1306_rect(ssd, 20, 20 + 20 + 20 + 20 + 10 + 20, 10, 10, true, true); // Amarelo (aceso)
    }
    else
    {
        ssd1306_rect(ssd, 20, 20 + 20 + 20 + 20 + 10 + 20, 10, 10, true, false); // Amarelo (aceso)
    }

    if (setor_3comando)
    {
        ssd1306_rect(ssd, 40, 20 + 20 + 20 + 10 + 20, 10, 10, true, true); // Amarelo (aceso)
    }
    else
    {
        ssd1306_rect(ssd, 40, 20 + 20 + 20 + 10 + 20, 10, 10, true, false); // Amarelo (aceso)
    }

    if (setor_4comando)
    {
        ssd1306_rect(ssd, 40, 20 + 20 + 20 + 20 + 10 + 20, 10, 10, true, true); // Amarelo (aceso)
    }
    else
    {
        ssd1306_rect(ssd, 40, 20 + 20 + 20 + 20 + 10 + 20, 10, 10, true, false); // Amarelo (aceso)
    }

    ssd1306_send_data(ssd);
}
