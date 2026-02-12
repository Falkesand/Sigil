namespace Sigil.Pe;

public readonly record struct PeSectionHeader(
    string Name,
    uint VirtualSize,
    uint VirtualAddress,
    uint SizeOfRawData,
    uint PointerToRawData);
