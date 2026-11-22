import assert from 'node:assert/strict';
import test from 'node:test';
import { allowsTextPreview, ownAppFilePath, parseAppFileListing } from '../src/owned_app_files.ts';

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
