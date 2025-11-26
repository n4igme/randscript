var _____WB$wombat$assign$function_____=function(name){return (self._wb_wombat && self._wb_wombat.local_init && self._wb_wombat.local_init(name))||self[name];};if(!self.__WB_pmw){self.__WB_pmw=function(obj){this.__WB_source=obj;return this;}}{
let window = _____WB$wombat$assign$function_____("window");
let self = _____WB$wombat$assign$function_____("self");
let document = _____WB$wombat$assign$function_____("document");
let location = _____WB$wombat$assign$function_____("location");
let top = _____WB$wombat$assign$function_____("top");
let parent = _____WB$wombat$assign$function_____("parent");
let frames = _____WB$wombat$assign$function_____("frames");
let opens = _____WB$wombat$assign$function_____("opens");
//Counter Animation
$(document).ready(function(){
						   
countanim = 0;
totalanim = $("#startcounter").text();
$("#startcounter").text('');
countanim = totalanim-300;
//alert(totalanim);

function countstarted() {
    if(countanim<totalanim){
	countanim++;
	$("#startcounter").text(countanim);
	}else{
	clearInterval(counteranim_interval);
	}
}
counteranim_interval = setInterval(countstarted, 5);

});

}
/*
     FILE ARCHIVED ON 18:56:33 Jun 07, 2020 AND RETRIEVED FROM THE
     INTERNET ARCHIVE ON 15:04:37 Nov 26, 2025.
     JAVASCRIPT APPENDED BY WAYBACK MACHINE, COPYRIGHT INTERNET ARCHIVE.

     ALL OTHER CONTENT MAY ALSO BE PROTECTED BY COPYRIGHT (17 U.S.C.
     SECTION 108(a)(3)).
*/
/*
playback timings (ms):
  captures_list: 0.71
  exclusion.robots: 0.061
  exclusion.robots.policy: 0.046
  esindex: 0.007
  cdx.remote: 27.678
  LoadShardBlock: 601.67 (3)
  PetaboxLoader3.datanode: 537.088 (5)
  PetaboxLoader3.resolve: 2483.599 (3)
  load_resource: 2676.698 (2)
*/