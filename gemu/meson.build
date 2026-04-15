gemu_ss = ss.source_set()

gemu_ss.add(files(
  './calling_conventions.c',
  './parameter_types.c',
  './cJSON.c',
  './fastcheck.c',
  './callbacks.c',
  './memorymapper.c',
  './utils.c',
  './mappedwaitinglist.c',
  './hooks.c',
  './gemu.c',
  './apidoc.c',
  './win_spector.c',
  './xxhash64.c',
  './dotnet_spector.c'
  ))

specific_ss.add_all(when: 'CONFIG_TCG', if_true: gemu_ss)
