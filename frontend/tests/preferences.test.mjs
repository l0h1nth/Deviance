import assert from 'node:assert/strict';
import test from 'node:test';
import {DEFAULT_COLUMNS,loadColumns,loadViews,saveColumns,saveCustomView} from '../src/services/preferences.ts';

class MemoryStorage{
  values=new Map();
  getItem(key){return this.values.get(key)??null}
  setItem(key,value){this.values.set(key,value)}
}

test('visible detection columns persist and reload',()=>{
  const storage=new MemoryStorage();
  assert.deepEqual(loadColumns(storage),DEFAULT_COLUMNS);
  saveColumns(['identity','risk','confidence'],storage);
  assert.deepEqual(loadColumns(storage),['identity','risk','confidence']);
});

test('custom saved views persist alongside default SOC views',()=>{
  const storage=new MemoryStorage();
  saveCustomView({id:'custom-test',name:'My triage',search:'vpn',severity:'high',visibleColumns:['identity','risk'],sortOrder:'oldest'},storage);
  const views=loadViews(storage);
  assert.ok(views.some(view=>view.id==='critical-unresolved'));
  assert.deepEqual(views.find(view=>view.id==='custom-test'),{id:'custom-test',name:'My triage',search:'vpn',severity:'high',visibleColumns:['identity','risk'],sortOrder:'oldest'});
});
