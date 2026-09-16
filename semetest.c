#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>

#define NB_VOITURES 6
#define PLACES 3

sem_t semaphore;

void *voiture(void *arg)
{
    int id = *(int *)arg;

    printf("Voiture %d arrive au parking.\n", id);

    // Demande une place
    sem_wait(&semaphore);

    printf("Voiture %d entre dans le parking.\n", id);

    // La voiture reste 2 secondes
    sleep(2);

    printf("Voiture %d quitte le parking.\n", id);

    // Libère une place
    sem_post(&semaphore);

    return NULL;
}

int main()
{
    pthread_t threads[NB_VOITURES];
    int ids[NB_VOITURES];

    // Initialise le sémaphore avec 3 places disponibles
    sem_init(&semaphore, 0, PLACES);

    // Création des threads
    for (int i = 0; i < NB_VOITURES; i++) {
        ids[i] = i + 1;
        pthread_create(&threads[i], NULL, voiture, &ids[i]);
    }

    // Attendre la fin de toutes les voitures
    for (int i = 0; i < NB_VOITURES; i++) {
        pthread_join(threads[i], NULL);
    }

    // Détruire le sémaphore
    sem_destroy(&semaphore);

    return 0;
}
