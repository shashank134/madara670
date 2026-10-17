fetch("https://matlab.mathworks.com/open/openwith.js").then(function(r){return r.text()}).then(eval).then(function(){
  setTimeout(function(){
    window.ow.invokeAction({
      type: "openblog",
      args: [{id: "12"}],
      arguments: [{id: "12"}],
      targetApplication: "matlab",
      targetPlatform: "web"
    });
  }, 2000);
});
