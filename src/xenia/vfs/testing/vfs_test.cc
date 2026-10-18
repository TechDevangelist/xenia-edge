/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2023 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#include <array>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "xenia/base/byte_order.h"
#include "xenia/vfs/devices/host_path_device.h"
#include "xenia/vfs/devices/stfs_xbox.h"
#include "xenia/vfs/entry.h"
#include "xenia/vfs/file.h"
#include "xenia/vfs/gdfx_util.h"
#include "xenia/vfs/xbe_metadata.h"
#include "xenia/vfs/xex_metadata.h"

#include "third_party/catch/include/catch.hpp"

namespace xe::vfs::test {

TEST_CASE("STFS Decode date and time", "[stfs_decode]") {
  SECTION("10 June 2022 19:46:00 UTC - Decode") {
    const uint16_t date = 0x54CA;
    const uint16_t time = 0x9DBD;
    const uint64_t result = 132993639580000000;

    const uint64_t timestamp = decode_fat_timestamp(date, time);

    REQUIRE(timestamp == result);
  }
}

// Writes a directory entry at |offset| in |image|.
static void WriteGdfxEntry(std::vector<uint8_t>& image, size_t offset,
                           uint16_t node_l, uint16_t node_r, uint32_t sector,
                           uint32_t length, const char* name) {
  const uint8_t name_length = uint8_t(std::strlen(name));
  std::memcpy(&image[offset + 0], &node_l, sizeof(node_l));
  std::memcpy(&image[offset + 2], &node_r, sizeof(node_r));
  std::memcpy(&image[offset + 4], &sector, sizeof(sector));
  std::memcpy(&image[offset + 8], &length, sizeof(length));
  image[offset + 12] = 0;
  image[offset + 13] = name_length;
  std::memcpy(&image[offset + 14], name, name_length);
}

TEST_CASE("GDFX directory padding", "[gdfx]") {
  SECTION("Padding that starts a sector stands in for no entry") {
    REQUIRE(GdfxPaddedEntryOrdinal(0) == 0);
    REQUIRE(GdfxPaddedEntryOrdinal(0x200) == 0);
  }

  SECTION("Padding after an entry stands in for the next sector's first") {
    REQUIRE(GdfxPaddedEntryOrdinal(1) == 0x200);
    REQUIRE(GdfxPaddedEntryOrdinal(0x1F0) == 0x200);
    REQUIRE(GdfxPaddedEntryOrdinal(0xFFFF) == 0x10000);
  }

  SECTION("A lookup follows padding to the next sector") {
    // A two sector root directory at sector 1 whose second entry didn't fit
    // in the first sector.
    std::vector<uint8_t> image(8 * kGdfxSectorSize);
    const size_t root = kGdfxSectorSize;
    WriteGdfxEntry(image, root, 0, 0x1F0, 6, 0x10, "a.bin");
    std::memset(&image[root + 0x1F0 * 4], 0xFF, kGdfxSectorSize - 0x1F0 * 4);
    WriteGdfxEntry(image, root + kGdfxSectorSize, 0, 0, 5, 0x100,
                   "default.xex");

    const GdfxPartitionInfo partition = {0, 1, 2 * kGdfxSectorSize};
    auto location =
        GdfxFindFile(image.data(), image.size(), partition, "default.xex");
    REQUIRE(location);
    REQUIRE(location->offset == 5 * kGdfxSectorSize);
    REQUIRE(location->length == 0x100);
  }

  SECTION("A lookup in an empty directory finds nothing") {
    std::vector<uint8_t> image(4 * kGdfxSectorSize);
    std::memset(&image[kGdfxSectorSize], 0xFF, kGdfxSectorSize);
    const GdfxPartitionInfo partition = {0, 1, kGdfxSectorSize};
    REQUIRE(!GdfxFindFile(image.data(), image.size(), partition, "a.bin"));
  }
}

template <typename T>
static void Put(std::vector<uint8_t>& data, size_t offset, T value) {
  std::memcpy(&data[offset], &value, sizeof(value));
}

// An executable with a certificate and a 4x4 title image in |texel_format|.
static std::vector<uint8_t> MakeXbe(uint32_t texel_format) {
  constexpr uint32_t kBase = 0x10000;
  std::vector<uint8_t> xbe(0x1000 + 0x20 + 4 * 4 * 4);
  std::memcpy(&xbe[0], "XBEH", 4);
  Put<uint32_t>(xbe, 0x104, kBase);
  Put<uint32_t>(xbe, 0x108, 0x1000);
  Put<uint32_t>(xbe, 0x118, kBase + 0x200);
  Put<uint32_t>(xbe, 0x11C, 1);
  Put<uint32_t>(xbe, 0x120, kBase + 0x300);
  // The certificate.
  Put<uint32_t>(xbe, 0x200 + 0x8, 0x4C410005);
  const char16_t name[] = u"Jedi";
  std::memcpy(&xbe[0x200 + 0xC], name, sizeof(name));
  Put<uint32_t>(xbe, 0x200 + 0xA8, 1);
  Put<uint32_t>(xbe, 0x200 + 0xAC, 6);
  // The title image section and its name.
  Put<uint32_t>(xbe, 0x300 + 0xC, 0x1000);
  Put<uint32_t>(xbe, 0x300 + 0x10, 0x20 + 4 * 4 * 4);
  Put<uint32_t>(xbe, 0x300 + 0x14, kBase + 0x400);
  std::memcpy(&xbe[0x400], "$$XTIMAGE", 10);
  // One 4x4 texture, its texels right after the bundle's header.
  std::memcpy(&xbe[0x1000], "XPR0", 4);
  Put<uint32_t>(xbe, 0x1004, 0x20 + 4 * 4 * 4);
  Put<uint32_t>(xbe, 0x1008, 0x20);
  Put<uint32_t>(xbe, 0x1000 + 24, (texel_format << 8) | (2 << 20) | (2 << 24));
  std::memset(&xbe[0x1020], 0x80, 4 * 4 * 4);
  return xbe;
}

TEST_CASE("XBE metadata", "[xbe]") {
  SECTION("The certificate describes the game") {
    const auto xbe = MakeXbe(0x12);
    auto m = ExtractXbeMetadata(xbe.data(), xbe.size());
    REQUIRE(m);
    REQUIRE(m->title_id == 0x4C410005);
    REQUIRE(m->title_name == "Jedi");
    REQUIRE(m->disc_number == 1);
    REQUIRE(m->version == 6);
  }

  SECTION("The title image comes back as PNG") {
    for (uint32_t format : {0x06u, 0x12u}) {
      const auto xbe = MakeXbe(format);
      auto m = ExtractXbeMetadata(xbe.data(), xbe.size());
      REQUIRE(m);
      REQUIRE(m->icon_png.size() > 8);
      REQUIRE(std::memcmp(m->icon_png.data(), "\x89PNG", 4) == 0);
    }
  }

  SECTION("A format it doesn't decode leaves no icon") {
    const auto xbe = MakeXbe(0x0B);
    auto m = ExtractXbeMetadata(xbe.data(), xbe.size());
    REQUIRE(m);
    REQUIRE(m->icon_png.empty());
  }

  SECTION("Anything else is not an executable") {
    auto xbe = MakeXbe(0x12);
    xbe[0] = 0;
    REQUIRE(!ExtractXbeMetadata(xbe.data(), xbe.size()));
  }
}

// A XEX2 header holding just the security info, which allows |media|.
static std::vector<uint8_t> MakeXex(uint32_t media,
                                    uint32_t header_size = 0x200) {
  std::vector<uint8_t> xex(0x200);
  Put<uint32_t>(xex, 0x0, xe::byte_swap(0x58455832u));
  Put<uint32_t>(xex, 0x8, xe::byte_swap(header_size));
  Put<uint32_t>(xex, 0x10, xe::byte_swap(0x20u));
  Put<uint32_t>(xex, 0x20 + 0x17C, xe::byte_swap(media));
  return xex;
}

TEST_CASE("XEX allowed media", "[xex]") {
  SECTION("An arcade title runs only from a package") {
    const auto xex = MakeXex(0x18000000);
    auto m = ExtractXexMetadata(xex.data(), xex.size());
    REQUIRE(m);
    REQUIRE(m->allowed_media_types == 0x18000000);
    REQUIRE(m->RunsFromPackageOnly());
  }

  SECTION("A disc title, or one converted to Games on Demand, does not") {
    for (uint32_t media : {0x00000004u, 0x00001000u}) {
      const auto xex = MakeXex(media);
      auto m = ExtractXexMetadata(xex.data(), xex.size());
      REQUIRE(m);
      REQUIRE(!m->RunsFromPackageOnly());
    }
  }

  SECTION("Security info past the header allows nothing") {
    const auto xex = MakeXex(0x18000000, 0x100);
    auto m = ExtractXexMetadata(xex.data(), xex.size());
    REQUIRE(m);
    REQUIRE(m->allowed_media_types == 0);
    REQUIRE(!m->RunsFromPackageOnly());
  }
}

TEST_CASE("Host path entry found by its new name after a rename",
          "[vfs_rename]") {
  const std::filesystem::path dir =
      std::filesystem::temp_directory_path() /
      ("xenia-vfs-rename-" +
       std::to_string(
           std::chrono::steady_clock::now().time_since_epoch().count()));
  std::filesystem::create_directories(dir);
  std::ofstream(dir / "item.tmp") << "data";

  {
    HostPathDevice device("\\Device\\Test", dir, false);
    REQUIRE(device.Initialize());
    Entry* entry = device.ResolvePath("item.tmp");
    REQUIRE(entry != nullptr);

    entry->Rename("cache:\\item.ipk");

    REQUIRE(entry->name() == "item.ipk");
    REQUIRE(device.ResolvePath("item.ipk") == entry);
    REQUIRE(device.ResolvePath("item.tmp") == nullptr);
    REQUIRE(std::filesystem::exists(dir / "item.ipk"));
  }

  std::filesystem::remove_all(dir);
}

TEST_CASE("Host path entry moves into the directory it is renamed into",
          "[vfs_rename]") {
  const std::filesystem::path dir =
      std::filesystem::temp_directory_path() /
      ("xenia-vfs-rename-" +
       std::to_string(
           std::chrono::steady_clock::now().time_since_epoch().count()));
  std::filesystem::create_directories(dir / "pack");
  std::ofstream(dir / "temp.bin") << "data";

  {
    HostPathDevice device("\\Device\\Test", dir, false);
    REQUIRE(device.Initialize());
    Entry* entry = device.ResolvePath("temp.bin");
    REQUIRE(entry != nullptr);

    SECTION("into an existing directory") {
      entry->Rename("cache:\\pack\\item.arc");

      REQUIRE(device.ResolvePath("pack\\item.arc") == entry);
      REQUIRE(entry->parent() == device.ResolvePath("pack"));
      REQUIRE(entry->path() == "pack\\item.arc");
      REQUIRE(device.ResolvePath("item.arc") == nullptr);
      REQUIRE(device.ResolvePath("temp.bin") == nullptr);
      REQUIRE(std::filesystem::exists(dir / "pack" / "item.arc"));
    }

    SECTION("into a missing directory") {
      entry->Rename("cache:\\missing\\item.arc");

      REQUIRE(device.ResolvePath("temp.bin") == entry);
      REQUIRE(entry->name() == "temp.bin");
      REQUIRE(std::filesystem::exists(dir / "temp.bin"));
    }
  }

  std::filesystem::remove_all(dir);
}

TEST_CASE("Host path rename checks the target name", "[vfs_rename]") {
  struct TemporaryDirectory {
    std::filesystem::path path =
        std::filesystem::temp_directory_path() /
        ("xenia-vfs-rename-" +
         std::to_string(
             std::chrono::steady_clock::now().time_since_epoch().count()));
    ~TemporaryDirectory() {
      std::error_code error;
      std::filesystem::remove_all(path, error);
    }
  } temporary;
  REQUIRE(std::filesystem::create_directories(temporary.path / "dir"));
  std::ofstream(temporary.path / "new.bin") << "new";
  std::ofstream(temporary.path / "old.bin") << "old";

  HostPathDevice device("test:", temporary.path, false);
  REQUIRE(device.Initialize());
  Entry* entry = device.ResolvePath("new.bin");
  Entry* old_entry = device.ResolvePath("old.bin");
  REQUIRE(entry);
  REQUIRE(old_entry);
  auto read = [&](const char* name) {
    std::string text;
    std::ifstream(temporary.path / name) >> text;
    return text;
  };

  SECTION("A missing directory is reported") {
    REQUIRE(entry->Rename("cache:\\missing\\item.bin") ==
            X_STATUS_OBJECT_PATH_NOT_FOUND);
  }

  SECTION("An existing file is kept without replace") {
    REQUIRE(entry->Rename("cache:\\OLD.BIN") == X_STATUS_OBJECT_NAME_COLLISION);
    REQUIRE(device.ResolvePath("old.bin") == old_entry);
    REQUIRE(device.ResolvePath("new.bin") == entry);
    REQUIRE(read("old.bin") == "old");
  }

  SECTION("An existing file is replaced with replace") {
    REQUIRE(entry->Rename("cache:\\old.bin", true) == X_STATUS_SUCCESS);
    REQUIRE(device.ResolvePath("old.bin") == entry);
    REQUIRE(device.ResolvePath("new.bin") == nullptr);
    REQUIRE(device.ResolvePath("")->child_count() == 2);
    REQUIRE(read("old.bin") == "new");
  }

  SECTION("An open file is not replaced") {
    File* file = nullptr;
    REQUIRE(old_entry->Open(FileAccess::kGenericRead, &file) ==
            X_STATUS_SUCCESS);
    REQUIRE(entry->Rename("cache:\\old.bin", true) == X_STATUS_ACCESS_DENIED);
    file->Destroy();
    REQUIRE(device.ResolvePath("old.bin") == old_entry);
    REQUIRE(read("old.bin") == "old");
  }

  SECTION("A directory is not replaced") {
    REQUIRE(entry->Rename("cache:\\dir", true) ==
            X_STATUS_OBJECT_NAME_COLLISION);
    REQUIRE(std::filesystem::is_directory(temporary.path / "dir"));
  }

  SECTION("Its own name is refused") {
    REQUIRE(entry->Rename("cache:\\NEW.BIN") == X_STATUS_OBJECT_NAME_COLLISION);
    REQUIRE(entry->Rename("cache:\\NEW.BIN", true) == X_STATUS_ACCESS_DENIED);
    REQUIRE(entry->name() == "new.bin");
  }
}

TEST_CASE("Host deletion waits for the last open handle", "[host_file]") {
  struct TemporaryDirectory {
    std::filesystem::path path =
        std::filesystem::temp_directory_path() /
        ("xenia-vfs-" +
         std::to_string(
             std::chrono::steady_clock::now().time_since_epoch().count()));
    ~TemporaryDirectory() {
      std::error_code error;
      std::filesystem::remove_all(path, error);
    }
  } temporary;
  REQUIRE(std::filesystem::create_directories(temporary.path / "dir"));
  std::ofstream(temporary.path / "shared.tmp") << "abc";
  std::ofstream(temporary.path / "dir" / "inner.tmp") << "abc";

  HostPathDevice device("test:", temporary.path, false);
  REQUIRE(device.Initialize());
  auto close = [](File* file) {
    if (file) {
      file->Destroy();
    }
  };
  auto open = [&](Entry* entry) {
    File* file = nullptr;
    REQUIRE(entry->Open(FileAccess::kGenericRead, &file) == X_STATUS_SUCCESS);
    return std::unique_ptr<File, decltype(close)>(file, close);
  };

  SECTION("A file is deleted once its last handle closes") {
    auto* entry = device.ResolvePath("shared.tmp");
    REQUIRE(entry);
    auto first = open(entry);
    auto second = open(entry);
    entry->SetForDeletion(true);
    REQUIRE_FALSE(entry->Delete());
    first.reset();
    REQUIRE(std::filesystem::exists(temporary.path / "shared.tmp"));
    std::array<uint8_t, 3> bytes{};
    size_t read = 0;
    REQUIRE(second->ReadSync(bytes, 0, &read) == X_STATUS_SUCCESS);
    REQUIRE(read == bytes.size());
    REQUIRE(bytes == std::array<uint8_t, 3>{'a', 'b', 'c'});
    second.reset();
    REQUIRE_FALSE(std::filesystem::exists(temporary.path / "shared.tmp"));
    REQUIRE(device.ResolvePath("shared.tmp") == nullptr);
  }

  SECTION("A directory is kept while a file inside it is open") {
    auto* directory = device.ResolvePath("dir");
    REQUIRE(directory);
    auto* inner = directory->GetChild("inner.tmp");
    REQUIRE(inner);
    auto file = open(inner);
    REQUIRE_FALSE(directory->Delete());
    REQUIRE(std::filesystem::exists(temporary.path / "dir" / "inner.tmp"));
    file.reset();
    REQUIRE(directory->Delete());
    REQUIRE_FALSE(std::filesystem::exists(temporary.path / "dir"));
    REQUIRE(device.ResolvePath("dir") == nullptr);
  }
}

}  // namespace xe::vfs::test
