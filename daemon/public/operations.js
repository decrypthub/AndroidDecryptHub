// Keep the live panel's guarded transport after unmounting task history.
(() => {
  const client=new AdhOperationClient();
  client.installGuard(window);
  window.adhOperations={
    setOperatorKey:key=>client.connect(String(key||'')),
  };
})();
