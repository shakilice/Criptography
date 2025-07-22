#include <iostream>
#include <utility>
#include <stdexcept>

using namespace std;

using Point = pair<int, int>;
const Point INF = {-1, -1};

int modinv(int a, int p) {
    int t = 0, newt = 1, r = p, newr = a;
    while (newr != 0) {
        int q = r / newr;
        tie(t, newt) = make_pair(newt, t - q * newt);
        tie(r, newr) = make_pair(newr, r - q * newr);
    }
    if (r > 1) throw runtime_error("No inverse");
    if (t < 0) t += p;
    return t;
}

Point add(Point P, Point Q, int a, int p) {
    if (P == INF) return Q;
    if (Q == INF) return P;

    int x1 = P.first, y1 = P.second;
    int x2 = Q.first, y2 = Q.second;

    if (x1 == x2 && (y1 + y2) % p == 0) return INF;

    int m;
    if (P == Q) {
        int num = (3 * x1 * x1 + a) % p;
        int den = modinv(2 * y1 % p, p);
        m = (num * den) % p;
    } else {
        int num = (y2 - y1 + p) % p;
        int den = modinv((x2 - x1 + p) % p, p);
        m = (num * den) % p;
    }

    int x3 = (m * m - x1 - x2 + p + p) % p;
    int y3 = (m * (x1 - x3) - y1 + p) % p;

    return {x3, y3};
}

Point multiply(Point P, int k, int a, int p) {
    Point R = INF;
    while (k > 0) {
        if (k % 2 == 1) R = add(R, P, a, p);
        P = add(P, P, a, p);
        k /= 2;
    }
    return R;
}

// Encode a small integer as a point on the curve (brute force trial)
Point encode_message(int m, int a, int b, int p) {
    for (int x = m * 10; x < m * 10 + 10; ++x) {
        int rhs = (x * x * x + a * x + b) % p;
        for (int y = 0; y < p; ++y) {
            if ((y * y) % p == rhs)
                return {x, y};
        }
    }
    throw runtime_error("Failed to encode message");
}

// ECC ElGamal Encryption
pair<Point, Point> encrypt(Point M, Point Q, Point G, int a, int p, int k) {
    Point C1 = multiply(G, k, a, p);
    Point kQ = multiply(Q, k, a, p);
    Point C2 = add(M, kQ, a, p);
    return {C1, C2};
}

// ECC ElGamal Decryption
Point decrypt(pair<Point, Point> cipher, int d, int a, int p) {
    Point C1 = cipher.first;
    Point C2 = cipher.second;
    Point dC1 = multiply(C1, d, a, p);
    Point neg_dC1 = {dC1.first, (-dC1.second + p) % p};
    return add(C2, neg_dC1, a, p);
}
int main() {
    int a = 2, b = 3, p = 97;
    Point G = {3, 6}; // base point

    // Alice's private and public key
    int d = 5; // private
    Point Q = multiply(G, d, a, p); // public

    int message = 7; // simple integer message
    Point M = encode_message(message, a, b, p);

    cout << "Original message encoded as point: (" << M.first << ", " << M.second << ")\n";

    int k = 10; // random ephemeral key (Bob chooses)
    auto cipher = encrypt(M, Q, G, a, p, k);

    cout << "Encrypted: C1=(" << cipher.first.first << ", " << cipher.first.second << ") ";
    cout << "C2=(" << cipher.second.first << ", " << cipher.second.second << ")\n";

    Point decrypted = decrypt(cipher, d, a, p);
    cout << "Decrypted point: (" << decrypted.first << ", " << decrypted.second << ")\n";
    return 0;
}
