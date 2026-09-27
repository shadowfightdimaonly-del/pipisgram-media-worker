export default {
  async fetch(request, env) {
    return new Response("Pipisgram Media Worker is working!", {
      status: 200,
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
      },
    });
  },
};