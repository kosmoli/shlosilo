/* Z6 link probe main — deliberately NO allocator support anywhere. */
extern void z6_probe_run(void);

int main(void) {
    z6_probe_run();
    return 0;
}
