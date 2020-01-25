#include<iostream>
#include<cstdlib>
#include<string>
#include<fstream>
#include "keyPbox.h"
#include "pbox.h"
#include "sbox.h"

#define N 64
#define R 16

using namespace std;

void pr(int* x,size_t n){
	for(int i=0;i<n;i++)
		cout<<x[i];
	cout<<endl;
}

void IIP(int *p){
	int tmp[N]={0};
	int i;
	for(i=0;i<N;i++) tmp[i]=p[i];
	for(i=0;i<N;i++) p[IIPmatrix[i]-1]=tmp[i];
}

void IP(int *p){
	int tmp[N]={0};
	int i;
	for(i=0;i<N;i++) tmp[i]=p[i];
	for(i=0;i<N;i++) p[IPmatrix[i]-1]=tmp[i];
}

void Xor(int *L,int *r,int n){
	int i;
	for(i=0;i<n;i++){
		L[i]=L[i]^r[i];
	}
}

void expand(int* p,int* res){
	int i;
	for(i=0;i<48;i++)
		res[i]=p[ EXmatrix[i]-1 ];
}

void Sboxhelp(int* p,int i,int* res){
	int r=p[0]*2+p[5];
	int c=p[1]*8+p[2]*4+p[3]*2+p[4];
	int data=0;
	switch(i){
	case 0:
		data=S1[r][c];
		break;
	case 1:
		data=S2[r][c];
		break;
	case 2:
		data=S3[r][c];
		break;
	case 3:
		data=S4[r][c];
		break;
	case 4:
		data=S5[r][c];
		break;
	case 5:
		data=S6[r][c];
		break;
	case 6:
		data=S7[r][c];
		break;
	case 7:
		data=S8[r][c];
		break;
	default: cout<<"error";
	}
	int k=3;
	while(data!=0){//data最大为15
		res[k]=data%2;
		data/=2;
		k--;
	}
	while(k>-1){
		res[k]=0;
		k--;
	}

}

void Sbox(int* lar,int* res){
	int i=0;
	for(i=0;i<8;i++){
		Sboxhelp(lar+i*6,i,res+i*4);
	}
}

void Pbox(int* p){
	int tmp[N/2];
	int i;
	for(i=0;i<N/2;i++) tmp[i]=p[i];//copy一份
	for(i=0;i<N/2;i++) p[i]=tmp[ Pmatrix[i]-1 ];
}

void func(int *p,int *key){
	int lar[48]={0};
	expand(p,lar);
	Xor(lar,key,48);//结果存在lar里面
	Sbox(lar,p);
	Pbox(p);
}

void kPbox(int *k){
	int tmp[N];
	int i;
	for(i=0;i<N;i++) tmp[i]=k[i];//copy一份
	for(i=0;i<56;i++) k[i]=tmp[ kPmatrix[i]-1 ];
}

void kRotate(int *k,int r){
	int i,j;
	int tmp;
	for(i=0;i<r;i++){//一次左移1位，一共r次
		tmp=k[0];
		for(j=0;j<27;j++)
			k[j]=k[j+1];
		k[j]=tmp;
	}
}

void kPbox2(int *kini,int* k){
	int i;
	for(i=0;i<48;i++){
		k[i]=kini[ kP2matrix[i]-1 ];
	}
}

void strTbit(string str,int* res){
	//int res[N]={0};
	int i,j;
	for(i=0;i<N;i++) res[i]=0;//初始化为0

	int len=8;
	if(str.length()<8) len=str.length();

	for(i=0;i<len;i++){
		res[8*i]=str[i];
	}
	for(i=0;i<N;i+=8){
		for(j=i+7;j>=i&&res[i]!=0;j--){
			res[j]=res[i]%2;
			res[i]/=2;
		}
	}//转换为bit流
	/*
	for(i=0;i<N;i++){
		cout<<res[i];
		if(i%8==7) cout<<" ";
	}
	*/
	
}

void bitTstr(int* cp,char* res){
	int i;
	for(i=0;i<N;i+=8){
		res[i/8]=cp[i]*128+cp[i+1]*64+cp[i+2]*32+cp[i+3]*16+cp[i+4]*8+cp[i+5]*4+cp[i+6]*2+cp[i+7];
	}
}

void decrypte(int* cp,int* keyini){
	ofstream resfile;
	resfile.open("plaintext.txt",ios::app);

	pr(cp,N);
	IIP(cp);
	pr(cp,N);

	int i;
	int tmp[32]={0};

	memcpy(tmp,cp+32,sizeof(int)*32);
	memcpy(cp+32,cp,sizeof(int)*32);
	memcpy(cp,tmp,sizeof(int)*32);//左右交换
	
	//key generation
	int keyinitial[56]={0};
	for(i=0;i<56;i++){
		keyinitial[i]=keyini[i];//将原始的密钥copy过来
	}
	int *C=keyinitial,*D=keyinitial+28;
	int key[R][48]={0};//把每一轮的出来的密钥都保存下来
	for(i=0;i<R;i++){
		//key generation
		kRotate(C,kRotation[i]);
		kRotate(D,kRotation[i]);
		kPbox2(keyinitial,key[i]);

	}
	
	for(i=0;i<R;i++){//16轮
		memcpy(tmp,cp,sizeof(int)*32);

		func(cp,key[15-i]);//左半边与key反应，结果存在左半边
		Xor(cp,cp+32,32);//与右半边反应，结果存在左半边
		
		memcpy(cp+32,tmp,sizeof(int)*32);//把旧L移到新R
		pr(cp,N);
	}

	IP(cp);
	pr(cp,N);

	char res[8];
	bitTstr(cp,res);//转换为string字符串

	for(i=0;i<8;i++) resfile<<res[i];

	resfile.close();
}

int main(){
	ifstream infile("ciphertext.txt");
	if(!infile.is_open()) return -1;//文件打开失败
	ofstream outfile("plaintext.txt");//创建并清空文件

	int cp[N]={0};
	char tmp;
	int i=0;
		
	string Key;
	cout<<"Please input the key:";
	while(Key.length()!=8) cin>>Key;//密钥长度为8 Bytes=64 bits
	//key initialized
	int keyinitial[N]={0};
	strTbit(Key,keyinitial);
	kPbox(keyinitial);//依然存到keyinitial的前56位里

	while(!infile.eof()){
		infile>>tmp;
		if(tmp=='0') cp[i]=0;
		else if(tmp=='1') cp[i]=1;
		else return -1;//error
		i++;

		if(i==N){
			decrypte(cp,keyinitial);
			i=0;
		}
	}
	//ciphertext肯定是64bits的倍数，否则就是加密错误了

	infile.close();
	outfile.close();
	system("pause");
	return 0;
}