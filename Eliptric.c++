#include<bits/stdc++.h>
#define ll long long int
#define en "\n"
using namespace std;
using Point= pair<int,int>;
const pair<int,int> INF={0,0};
int modinv(int a, int m) {
    if(__gcd(a,m)!=1)return -1;
    int m0 = m;
    int x0 = 0, x1 = 1;
    if (m == 1)
        return 0;
    while (a > 1) {
        int q = a / m;
        int t = m;
        m = a % m;
        a = t;
        int temp = x0;
        x0 = x1 - q * x0;
        x1 = temp;
    }
    if (x1 < 0)
        x1 += m0;
   // cout<<x1<<en;
    return x1;
}
Point add(Point P, Point Q, int a, int p) {
    if (P == INF) return Q;
    if (Q == INF) return P;

    int x1 = P.first, y1 = P.second;
    int x2 = Q.first, y2 = Q.second;

    if (x1 == x2&&(y1+y2)%p==0) return INF;

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

    return {(x3+p)%p, (y3+p)%p};
    
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

int main(){
    int p=13,a=1,b=2;
    Point g={7,1};
     cout<<"Enter the Alice private key"<<en;
     int A;
     cin>>A;
     Point pa=multiply(g,A, a, p);
     cout<<pa.first<<" "<<pa.second<<en;
     cout<<"enter the bob privet key"<<en;
     int B;
     cin>>B;
     Point pb=multiply(g,B,a,p);
     cout<<pb.first<<" "<<pb.second<<en;
     Point k1=multiply(pb,A,a,p);
     Point k2=multiply(pa,B,a,p);
     cout<<"shared key k1 and k2 is:"<<en;
     cout<<"k1 "<<k1.first<<" "<<k1.second<<en;
     cout<<"k2 "<<k2.first<<" "<<k2.second<<en;
    return 0;
}
