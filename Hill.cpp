#include<bits/stdc++.h>
#define ll lonfg long int
#define int long long
#define en "\n"
using namespace std;
const int m=26;
vector<vector<int> >key;
int M_inverse(int a, int m) {
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
struct MAT{
    vector<vector<int>> mat_inv(vector<vector<int>> v, int det) {
    int n = v.size();
    vector<vector<int>> inv(n, vector<int>(n));
    det = (det % m + m) % m;
    int det_inv = M_inverse(det, m);  

    if (n == 2) {
        inv[0][0] = v[1][1];
        inv[0][1] = -v[0][1];
        inv[1][0] = -v[1][0];
        inv[1][1] = v[0][0];
        for (int i = 0; i < 2; ++i)
            for (int j = 0; j < 2; ++j)
                inv[i][j] = ((inv[i][j] * det_inv) % m + m) % m;
    } else if (n == 3) {
        vector<vector<int>> co(3, vector<int>(3));

        co[0][0] =  (v[1][1]*v[2][2] - v[1][2]*v[2][1]);
        co[0][1] = -(v[1][0]*v[2][2] - v[1][2]*v[2][0]);
        co[0][2] =  (v[1][0]*v[2][1] - v[1][1]*v[2][0]);

        co[1][0] = -(v[0][1]*v[2][2] - v[0][2]*v[2][1]);
        co[1][1] =  (v[0][0]*v[2][2] - v[0][2]*v[2][0]);
        co[1][2] = -(v[0][0]*v[2][1] - v[0][1]*v[2][0]);

        co[2][0] =  (v[0][1]*v[1][2] - v[0][2]*v[1][1]);
        co[2][1] = -(v[0][0]*v[1][2] - v[0][2]*v[1][0]);
        co[2][2] =  (v[0][0]*v[1][1] - v[0][1]*v[1][0]);

        // Transpose of cofactor matrix (adjugate)
        for (int i = 0; i < 3; ++i)
            for (int j = 0; j < 3; ++j)
                inv[i][j] = ((co[j][i] * det_inv) % m + m) % m;
    }

    return inv;
}

  int determinant(vector<vector<int>> v) {
    int n = v.size(); 
    if (n == 2) {
        return v[0][0] * v[1][1] - v[0][1] * v[1][0];
       }
    else {
        int a = v[0][0], b = v[0][1], c = v[0][2];
        int d = v[1][0], e = v[1][1], f = v[1][2];
        int g = v[2][0], h = v[2][1], i = v[2][2];

        return (a * (e * i - f * h)- b * (d * i - f * g) + c * (d * h - e * g))%m;
      }
    
    }
    vector<int> mul(vector<vector<int>> v1, vector<int> v2) {
    int n = v1.size(); 
    vector<int> result(n, 0);
    for (int i = 0; i < n; i++) {
        int sum = 0;
        for (int j = 0; j < n; j++) {
            sum = (sum + v1[i][j] * v2[j]) % m;
        }
        result[i] = (sum%m+ m) % m; 
    }
    return result;
  }

};
MAT M;
void convert(vector<string> v){
   int sz=v.size();
   key.resize(sz,vector<int> (sz));
   for(int i=0;i<sz;i++){
    for(int j=0;j<sz;j++){
        key[i][j]=v[i][j]-'A';
    }
   }

}
string encription(string ms){
 int sz=ms.size();
 int di=key.size();
  int g=(di-sz%di)%di;
 for(int i=0;i<g;i++)ms+='X';
  string ans="";
  vector<int> temp;
  for(int i=0;i<ms.size();i++){
    temp.push_back(ms[i]-'A');
    if(temp.size()==di){
        vector<int> t=M.mul(key,temp);
        for(int j=0;j<di;j++)ans+=('A'+t[j]);
        temp.clear();
    }
  }
  return ans;
}
string decription(string ms){
   int sz=ms.size();
 int di=key.size();
  string ans="";
  vector<int> temp;
  for(int i=0;i<ms.size();i++){
    temp.push_back(ms[i]-'A');
    if(temp.size()==di){
        int d=M.determinant(key);
        d=(d%m+m)%m;

        vector<vector<int>> I_key=M.mat_inv(key,d);
        vector<int> t=M.mul(I_key,temp);
        for(int j=0;j<di;j++)ans+=('A'+t[j]);
        temp.clear();
    }
  }
  return ans;
}
 void sol(){
   // cout<<"Enter the dimention of the key string"<<en;
    int di;cin>>di;
  //  cout<<"Enter the "<<di<<"*"<<di<<" key string matrics"<<en;
    vector<string> s1;
    for(int i=0;i<di;i++){
        string s;
        cin>>s;
        s1.push_back(s);
    }
    
    convert(s1);
    int d=M.determinant(key);
    if(__gcd(abs(d),m)!=1||d==0){
        cout<<"Please provide the appropiate key";
        return;
    }
  //  cout<<"Enter the plin text in capital letter without space"<<en;
    string s2;
    cin>>s2;
    string chiper=encription(s2);
    cout<<"encripted message is:"<<en;
    cout<<chiper<<en;
    string decript=decription(chiper);
    cout<<"Original message is:"<<en;
    cout<<decript<<en;
 }
int32_t main(){
     int t=1;
    // cin>>t;
     while(t--){
        sol();
     }
   return 0;
}
