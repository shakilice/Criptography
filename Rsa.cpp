#include<bits/stdc++.h>
using namespace std;
struct mod_inverse{
  int md_inv(int a, int m){
    int x, y;
    int g=extended(a,m,x,y);
    if(g!=1)return -1;
    return (x+m)%m;
  }
  int extended(int a,int b, int &x, int &y){
       if(b==0){
        x=1,y=0;
        return a;
       }
       int x1, y1;
       int g=extended(b,a%b,x1,y1);
        x=y1;
        y=x1-(a/b)*y1;
       return g;
  }
}Md;
int exp(int a,int p,int m){
    if(p==0)return 1;
    if(p%2==1){
        int x=(exp(a,p-1,m)*a)%m;
        return x;
    }
    else{
        int x=exp(a,p/2,m)%m;
        return (x*x)%m;
    }
}
int main(){
    int p,q;
    //cout<<"Enter the two prime number"<<endl;
    cin>>p>>q;
    int n=p*q;
    int fi=(p-1)*(q-1);
    int pb;
    for(int i=2;i<fi;i++){
        int x=__gcd(i,fi);
        if(x==1){
            pb=i;
            break;
        }
    }
    int pr=Md.md_inv(pb,fi);
    int mes;
   // cout<<"Enter the input message"<<endl;
    cin>>mes;
    int c=exp(mes,pb,n);
    int d=exp(c,pr,n);
   // cout<<"Encrip and decript message"<<endl;
    cout<<c<<" "<<d<<endl;
    return 0;
}
