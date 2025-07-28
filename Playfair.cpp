#include<bits/stdc++.h>
using namespace std;
string key;
char mat[10][10];
int col[30];
int row[30];
void fill(){
  set<char> st;
  for(int i=0;i<26;i++){
    char t='a'+i;
    st.insert(t);
  }
  st.erase('i');
  st.erase('j');
  mat[2][2]='i';
  row['i'-'a']=2,col['i'-'a']=2;
  row['j'-'a']=2,col['j'-'a']=2;
  int cnt=0;
  for(int i=0;i<5;i++){
    for(int j=0;j<5;j++){
        if(i==2&&j==2)continue;
        if(cnt<key.size()){
            char t=key[cnt];
            mat[i][j]=t;
            st.erase(t);
            row[t-'a']=i,col[t-'a']=j;
            cnt++;
        }
        else{
            auto it=st.begin();
            char t=*it;
            mat[i][j]=t;
            row[t-'a']=i,col[t-'a']=j;
            st.erase(t);
        }
    }
  }
  for(int i=0;i<5;i++){
    for(int j=0;j<5;j++){
      cout<<mat[i][j]<<" ";
    }
    cout<<endl;
  }
}
string post(char t1,char t2){
    int r1=row[t1-'a'],c1=col[t1-'a'];
    int r2=row[t2-'a'],c2=col[t2-'a'];
    if(r1==r2){
       c1++,
       c2++;
       if(c2==5)c2=0;
       if(c2==5)c2=0;
    }
    else if(c1==c2){
      r1++,r2++;
      if(r2==5)r2=0;
      if(r1==5)r1=0;
    }
    else{
       swap(c1,c2);
    }
    string tm="";
    tm+=mat[r1][c1];
    tm+=mat[r2][c2];
    return tm;
}
string pre(char t1,char t2){
   int r1=row[t1-'a'],c1=col[t1-'a'];
    int r2=row[t2-'a'],c2=col[t2-'a'];
    if(r1==r2){
       c1--,
       c2--;
       if(c2==-1)c2=4;
       if(c2==-1)c2=4;
    }
    else if(c1==c2){
      r1--,r2--;
      if(r2==-1)r2=4;
      if(r1==-1)r1=4;
    }
    else{
       swap(c1,c2);
    }
    string tm="";
    tm+=mat[r1][c1];
    tm+=mat[r2][c2];
    return tm;
}
string encrip(string ms){
   string tm="";
   for(int i=0;i<ms.size();i++){
      if(i==ms.size()-1){
           tm+=ms[i];
           tm+='x';
      }
      else{
        if(ms[i]==ms[i+1]){
            tm+=ms[i];
            tm+='x';
        }
        else{
            tm+=ms[i];
            tm+=ms[i+1];
            i++;
        }
      }
   }
   string ans="";
   for(int i=0;i<tm.size();i+=2){
      char t1=tm[i];
      char t2=tm[i+1];
      ans=ans+post(t1,t2);
   }
   return ans;
}
string decrip(string ms){
 string ans="";
 for(int i=0;i<ms.size();i+=2){
  char t1=ms[i],t2=ms[i+1];
  ans=ans+pre(t1,t2);
  }
  return ans;
}
int main(){
  cout<<"Enter the key"<<endl;
    cin>>key;
    fill();
    string s1="playfairexample";
    string b=encrip(s1);
    cout<<"Encripted text is:"<<endl;
    cout<<b<<endl;
    string c=decrip(b);
    cout<<"Decrepted text is:"<<endl;
    cout<<c<<endl;

    return 0;
}
