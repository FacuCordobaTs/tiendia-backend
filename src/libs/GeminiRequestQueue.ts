/**
 * Clase para gestionar una cola de solicitudes a la API de Gemini
 * con un límite de 10 solicitudes por minuto
 */

type QueueItem = {
  payload: any;
  resolve: (value: any) => void;
  reject: (reason: any) => void;
  workerUrl: string;
};

export class GeminiRequestQueue {
  private queue: QueueItem[] = [];
  private availableTokens: number = 10;
  private processing: boolean = false;
  private static instance: GeminiRequestQueue;

  private constructor() {
    // Reabastecer 10 tokens cada 60 segundos
    setInterval(() => {
      this.availableTokens = 10;
      this.processQueue();
    }, 60000);
  }

  /**
   * Obtiene la instancia única de la cola (patrón Singleton)
   */
  public static getInstance(): GeminiRequestQueue {
    if (!GeminiRequestQueue.instance) {
      GeminiRequestQueue.instance = new GeminiRequestQueue();
    }
    return GeminiRequestQueue.instance;
  }

  /**
   * Encola una solicitud a la API de Gemini
   * @param payload Datos a enviar a la API
   * @param workerUrl URL del worker de Cloudflare
   * @returns Promesa que se resolverá con la respuesta de la API
   */
  public enqueue(payload: any, workerUrl: string): Promise<any> {
    return new Promise((resolve, reject) => {
      this.queue.push({
        payload,
        resolve,
        reject,
        workerUrl
      });
      
      // Intentar procesar la cola inmediatamente
      this.processQueue();
    });
  }

  /**
   * Procesa las solicitudes en la cola según los tokens disponibles
   */
  private async processQueue(): Promise<void> {
    // Evitar procesamiento concurrente
    if (this.processing || this.queue.length === 0 || this.availableTokens === 0) {
      return;
    }

    this.processing = true;

    try {
      while (this.queue.length > 0 && this.availableTokens > 0) {
        const item = this.queue.shift();
        if (!item) continue;

        this.availableTokens--;
        console.log(`Procesando solicitud. Tokens restantes: ${this.availableTokens}`);

        try {
          const response = await fetch(item.workerUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(item.payload),
          });

          if (!response.ok) {
            const errorBody = await response.text();
            console.error("Error desde el worker:", response.status, errorBody);
            item.reject(new Error(`Error desde el worker: ${response.statusText} - ${errorBody}`));
          } else {
            const data = await response.json();
            item.resolve(data);
          }
        } catch (error) {
          console.error("Error al procesar solicitud en cola:", error);
          item.reject(error);
        }
      }
    } finally {
      this.processing = false;
      
      // Si aún hay elementos en la cola y tokens disponibles, continuar procesando
      if (this.queue.length > 0 && this.availableTokens > 0) {
        this.processQueue();
      }
    }
  }

  /**
   * Obtiene el número de solicitudes pendientes en la cola
   */
  public getPendingCount(): number {
    return this.queue.length;
  }

  /**
   * Obtiene el número de tokens disponibles actualmente
   */
  public getAvailableTokens(): number {
    return this.availableTokens;
  }
}