import assert from 'node:assert/strict';
import test from 'node:test';
import { allowsTextPreview, ownAppFilePath, parseAppFileListing, parseOwnedTextEdit, decodeOwnedPreview, decodeDemoFileReply } from '../src/owned_app_files.ts';

test('owned debug directory paths are bounded, relative and ordinary', () => {
  assert.equal(ownAppFilePath(''),'');
  assert.equal(ownAppFilePath('sub folder/记录.txt'),'sub folder/记录.txt');
  for (const path of ['../outside','sub/../outside','/outside','sub\\.\\outside','sub//name','sub/.temp','name\nx','\x00','a/'.repeat(25)+'b']) {
    assert.throws(()=>ownAppFilePath(path),{status:400});
  }
});

test('the directory protocol preserves names and metadata but does not make special names browsable', () => {
  const data=Buffer.from(['example.txt','file','55','1000','子目录','directory','8','1200','../outside','file','2','1000',''].join('\0'));
  const result=parseAppFileListing(data);
  assert.deepEqual(result,{limited:false,entries:[
    {name:'子目录',type:'directory',size:null,modifiedAt:1200000},
    {name:'example.txt',type:'file',size:55,modifiedAt:1000000},
  ]});
  assert.deepEqual(parseAppFileListing(Buffer.alloc(0)),{entries:[],limited:false});
  assert.throws(()=>parseAppFileListing(Buffer.from('malformed')),{status:502});
});

test('preview is for ordinary text formats only', () => {
  assert.equal(allowsTextPreview('notes/日志.txt'),true);
  assert.equal(allowsTextPreview('example.JSON'),true);
  assert.equal(allowsTextPreview('library.so'),false);
  assert.equal(allowsTextPreview('archive.apk'),false);
  assert.equal(allowsTextPreview('some.dex'),false);
});
test('ADB text wrapping cannot change the bytes used for preview or its revision',()=>{
  const expected=Buffer.from('手机文件\n第二行\n','utf8');
  const wrapped=Buffer.from(expected.toString('base64').replace(/.{4}/g,'$&\r\n'));
  assert.deepEqual(decodeOwnedPreview(wrapped,true),expected);
  assert.throws(()=>decodeOwnedPreview(Buffer.from('broken???'),true),{status:502});
});
test('owned text save input is bounded and carries the original file version',()=>{
  const revision='a'.repeat(64);
  assert.deepEqual(parseOwnedTextEdit({text:'授权测试\n',revision}),{bytes:Buffer.from('授权测试\n'),revision});
  for(const body of [{text:'a',revision:'invalid'},{text:'a\r\n',revision},{text:'a\0',revision},
      {text:'a',revision,path:'elsewhere'},{text:'\ud800',revision}]){
    assert.throws(()=>parseOwnedTextEdit(body),{status:400});
  }
  assert.throws(()=>parseOwnedTextEdit({text:'x'.repeat(32769),revision}),{status:413});
});

test('Demo reply decoding preserves file bytes and rejects stale or invalid replies',()=>{
  const bytes=Buffer.from('真机读取\n','utf8');
  assert.deepEqual(decodeDemoFileReply(Buffer.from('Result: Bundle[{adhFile=200.'+bytes.toString('base64url')+'}]\r\n')),bytes);
  assert.throws(()=>decodeDemoFileReply(Buffer.from('Result: Bundle[{adhFile=409.}]')),{status:409});
  assert.throws(()=>decodeDemoFileReply(Buffer.from('Result: Bundle[{adhFile=200.Zh}]')),{status:502});
  assert.throws(()=>decodeDemoFileReply(Buffer.from('Error: No content provider found')),{status:502});
});
