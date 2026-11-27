/** Pure board scoping shared by Host policy and the panel. */
export const CAPTURE_BOARDS=['crypto','system','net'] as const;
export type CaptureBoard=typeof CAPTURE_BOARDS[number];
export const BOARD_FEATURES={crypto:['digest','hmac','symmetric','asymmetric','aead'],system:['system','file'],net:['tls']} as const;
export const BOARD_MASK={crypto:47,system:192,net:16} as const;
export const BOARD_LABEL={crypto:'加解密',system:'系统',net:'网络'} as const;
export function captureBoards(value?:Partial<Record<CaptureBoard,boolean>>){return {crypto:value?.crypto!==false,system:value?.system!==false,net:value?.net!==false};}
export function featureBoard(key:string):CaptureBoard{return key==='tls'?'net':key==='system'||key==='file'?'system':'crypto';}
export function featureCaptureEnabled(config:any,key:string){return config.features[key].enabled&&captureBoards(config.boards)[featureBoard(key)];}
export function captureMethodActive(m:any){return m.backend==='java'?m.active===true:Number(m.ownedSlots)>0;}
export function boardCaptureState(views:any[],board:CaptureBoard){const methods=views.flatMap(v=>(v.runtime?.methods??[]).filter((m:any)=>m.families&BOARD_MASK[board]));const active=methods.filter(captureMethodActive).length,expected=views.reduce((n,v)=>n+new Set(BOARD_FEATURES[board].flatMap(k=>featureCaptureEnabled(v.config,k)?v.config.features[k].methods:[])).size,0),uncertain=methods.some((m:any)=>Number(m.changedSlots)>0||Number(m.unreadableSlots)>0);return {active,checked:active>0,partial:active>0&&(active!==expected||uncertain),uncertain};}
