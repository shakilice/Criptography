#include<bits/stdc++.h>
using namespace std;
//B represent number of bit in one block
const int B=16;
string byte_to_string(vector<bitset<B> > v){
    string ans="";
    for(int i=0;i<v.size();i++){
        bitset<B> b=v[i];
        int c=0;
        for(int i=0;i<B;i++){
         int d=pow(2,i);
         c+=(d*b[i]);
        }
        ans+=(char)c;
    }
    return ans;
}
vector<bitset<B> > string_to_byte(string s){
    vector<bitset<B> > ans;
    for(int i=0;i<s.size();i++){
        int c=(int)s[i];
        bitset<B> b(c);
        ans.push_back(b);
    }
    return ans;
}
bitset<B> XOR(bitset<B> b1,bitset<B> b2){
    bitset<B> b=(b1^b2);
    return b;
}
bitset<B> ran_dom(){
    int a=9;//this valu any zero to 255 if B=8 bit
    bitset<B> b(a);
    return b;
}
bitset<B> key_to_byte(string key){
  bitset<B> b;
  int c=-1;
  for(int i=0;i<key.size();i++){
    bitset<8> a((int)key[i]);
    for(int j=0;j<8;j++){
        c++;
        b[c]=a[j];
    }
  }
  return b;
}
string encrip(string s,string key){
     cout<<1<<endl;
    bitset<B> iv=ran_dom();
   vector<bitset<B> > v=string_to_byte(s);
   vector<bitset<B> > ans;
   bitset<B> k=key_to_byte(key);
   for(int i=0;i<v.size();i++){
     bitset<B> a=XOR(v[i],iv);
     bitset<B> b=XOR(k,a);
     iv=b;
     ans.push_back(b);
   }
   cout<<"encripted bits stream is:"<<endl;
   for(int i=0;i<ans.size();i++)cout<<ans[i];
   cout<<endl;
   string tm=byte_to_string(ans);
   return tm;
}
string decript(string s,string key){
    bitset<B> iv=ran_dom();
   vector<bitset<B> > v=string_to_byte(s);
   vector<bitset<B> > ans;
   bitset<B> k=key_to_byte(key);
   for(int i=0;i<v.size();i++){
     bitset<B> a=XOR(v[i],k);
     bitset<B> b=XOR(iv,a);
     iv=v[i];
     ans.push_back(b);
   }
   for(int i=0;i<ans.size();i++){
    cout<<ans[i]<<endl;
   }
   string tm=byte_to_string(ans);
   return tm;
}

int main(){
      string s="Amishakilahammed lets break this";
      string key="RT";
      string a=encrip(s,key);
      string b=decript(a,key);
      cout<<"Decript message is:"<<endl;
      cout<<b<<endl;
    return 0;
}
