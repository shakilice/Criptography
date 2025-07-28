#include<bits/stdc++.h>
using namespace std;
string encrip(string ms,int key){
  string ans="";
  key=key%26;
  for(int i=0;i<ms.size();i++){
    if(ms[i]>='A'&&ms[i]<='Z'){
       int  t=ms[i]+key;
       if(t>'Z'){
        t='A'+(t-'Z')-1;
       }
       ans+=(char)t;

    }
    else if(ms[i]>='a'&&ms[i]<='z'){
         int  t=ms[i]+key;
       if(t>'z'){
        t='a'+(t-'z')-1;
       }
       ans+=(char)t;
    }
    else ans+=ms[i];
  }
  return ans;
}
string decrip(string ms,int key){
    string ans="";
    key=key%26;
    for(int i=0;i<ms.size();i++){
        if(ms[i]>='A'&&ms[i]<='Z'){
           int t=ms[i]-key;
           if(t<'A'){
            t='Z'-('A'-t)+1;
           }
           ans+=(char)t;
        }
        else if(ms[i]>='a'&&ms[i]<='z'){
          int t=ms[i]-key;
           if(t<'a'){
            t='z'-('a'-t)+1;
           }
           ans+=(char)t;
        }
        else ans+=ms[i];
    }
    return ans;
}
int main(){
    string a="ABS123xyzXdr^&DFG 234@#$";
    string b=encrip(a,1);
    cout<<"Encripted text is:"<<endl;
    cout<<b<<endl;
    string c=decrip(b,1);
    cout<<"Decrepted text is:"<<endl;
    cout<<c<<endl;
}
