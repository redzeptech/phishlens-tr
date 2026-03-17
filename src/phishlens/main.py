"""PhishLens TR - CLI giriş noktası.

Paket kurulduğunda `phishlens` komutu bu modüldeki main() fonksiyonunu çalıştırır.
"""

from phishlens.core import main

__all__ = ["main"]

if __name__ == "__main__":
    main()
