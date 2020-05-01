(this.webpackJsonptemplate=this.webpackJsonptemplate||[]).push([[0],{42:function(e,t,a){e.exports=a(74)},73:function(e,t,a){},74:function(e,t,a){"use strict";a.r(t);var n=a(0),s=a.n(n),r=a(19),i=a.n(r),c=a(6),l=a(7),o=a(9),u=a(8),m=a(3),p=function(e,t){var a=arguments.length>2&&void 0!==arguments[2]?arguments[2]:null;return{type:"GET_ERRORS",payload:{msg:e,status:t,id:a}}},h=function(){return{type:"CLEAR_ERRORS"}},d=a(18),g=a.n(d),E=a(2),f=function(e){Object(o.a)(a,e);var t=Object(u.a)(a);function a(){return Object(c.a)(this,a),t.apply(this,arguments)}return Object(l.a)(a,[{key:"render",value:function(){var e=this.props,t=e.user,a=e.isLoading,n=e.isAuth;return s.a.createElement("div",{className:"header-section"},s.a.createElement("div",{className:"container flex-wrap"},s.a.createElement(m.b,{exact:!0,className:"header-logo",to:"/"},"Template"),s.a.createElement("ul",{className:"header-nav"},!1!==a||n?s.a.createElement("span",null,s.a.createElement("li",null,s.a.createElement("h3",{className:"user-title"},n&&t.username)),s.a.createElement("li",null,s.a.createElement(m.b,{exact:!0,className:"btn simple",to:"/"},"Home")),s.a.createElement("li",null,s.a.createElement(m.b,{exact:!0,className:"btn simple",to:"/admin"},"Admin")),s.a.createElement("li",null,s.a.createElement("div",{onClick:this.props.logout,className:"btn simple"},"Logout"))):s.a.createElement("span",null,s.a.createElement("li",null,s.a.createElement(m.b,{exact:!0,className:"btn simple",to:"/login"},"Login")),s.a.createElement("li",null,s.a.createElement(m.b,{exact:!0,className:"btn simple",to:"/register"},"Register"))))))}}]),a}(n.Component),b=Object(E.b)((function(e){return{isAuth:e.auth.isAuthenticated,isLoading:e.auth.isLoading,user:e.auth.user}}),{logout:function(){return function(e){g.a.get("/user/logout").then((function(){e({type:"LOGOUT_SUCCESS"})}))}}})(f),v=function(e){Object(o.a)(a,e);var t=Object(u.a)(a);function a(){return Object(c.a)(this,a),t.apply(this,arguments)}return Object(l.a)(a,[{key:"render",value:function(){var e=this.props,t=e.isAuth;e.isLoading,e.items;return s.a.createElement("div",{className:"main-section"},s.a.createElement("h2",null,"Dashboard ( ",t?s.a.createElement("span",null,"Logged In"):s.a.createElement("span",null,"Logged Out"),")"))}}]),a}(n.Component),O=Object(E.b)((function(e){return{isAuth:e.auth.isAuthenticated,isLoading:e.auth.isLoading}}),{})(v),y=function(e){Object(o.a)(a,e);var t=Object(u.a)(a);function a(){return Object(c.a)(this,a),t.apply(this,arguments)}return Object(l.a)(a,[{key:"render",value:function(){this.props.isAuth;return s.a.createElement("div",{className:"main-section"},s.a.createElement("h2",null,"Admin Panel"))}}]),a}(n.Component),A=Object(E.b)((function(e){return{isAuth:e.auth.isAuthenticated,isLoading:e.auth.isLoading}}),{})(y),N=a(16),j=a(13),L=function(e){Object(o.a)(a,e);var t=Object(u.a)(a);function a(){var e;Object(c.a)(this,a);for(var n=arguments.length,s=new Array(n),r=0;r<n;r++)s[r]=arguments[r];return(e=t.call.apply(t,[this].concat(s))).state={mail:"",pass:"",msg:{}},e.onChange=function(t){var a=t.target,n=a.value,s=a.name;e.setState(Object(N.a)({},s,n))},e.onSubmit=function(t){t.preventDefault();var a={username:e.state.mail,password:e.state.pass};e.props.login(a)},e}return Object(l.a)(a,[{key:"componentDidUpdate",value:function(e){if(!0===this.props.isAuth)return this.props.clearErrors(),this.props.history.push("/");var t=this.props.error;t!==e.error&&("LOGIN_FAIL"===t.id?this.setState({msg:t.msg}):this.setState({msg:{}}))}},{key:"componentWillUnmount",value:function(){this.props.clearErrors()}},{key:"redir",value:function(){window.location="https://localhost:5000/user/github"}},{key:"render",value:function(){return s.a.createElement("div",{className:"login-section"},s.a.createElement("h2",{className:"log-title"},"Login"),s.a.createElement("div",{className:"flex-wrap center"},s.a.createElement("form",{onSubmit:this.onSubmit,className:"add-form",autoComplete:"off"},s.a.createElement("div",{className:"simple-input"},s.a.createElement("input",{type:"text",name:"mail",placeholder:"Mail",value:this.state.mail,onChange:this.onChange,className:this.state.msg.mail&&"error"})," ",this.state.msg.mail&&s.a.createElement("div",{className:"exclam"},s.a.createElement("img",{src:"img/exclam-ico.png",alt:""}))),s.a.createElement("div",{className:"simple-input"},s.a.createElement("input",{type:"password",name:"pass",placeholder:"Password",value:this.state.pass,onChange:this.onChange,className:this.state.msg.pass&&"error"})," ",this.state.msg.pass&&s.a.createElement("div",{className:"exclam"},s.a.createElement("img",{src:"img/exclam-ico.png",alt:""}))),s.a.createElement("button",{type:"submit",className:"btn"},"Sign In"),s.a.createElement("a",{onClick:this.redir},"Github"))))}}]),a}(s.a.Component),S=Object(j.f)(Object(E.b)((function(e){return{isAuth:e.auth.isAuthenticated,error:e.error}}),{login:function(e){return function(t){var a=JSON.stringify(e);g.a.post("/user/login",a,{headers:{"Content-type":"application/json"}}).then((function(e){console.log(e.status),t({type:"LOGIN_SUCCESS",payload:e.data})})).catch((function(e){console.log(e.response),t(p(e.response.data,e.response.status,"LOGIN_FAIL")),t({type:"LOGIN_FAIL"})}))}},clearErrors:h})(L)),R=function(e){Object(o.a)(a,e);var t=Object(u.a)(a);function a(){var e;Object(c.a)(this,a);for(var n=arguments.length,s=new Array(n),r=0;r<n;r++)s[r]=arguments[r];return(e=t.call.apply(t,[this].concat(s))).state={login:"",mail:"",pass:"",pass2:"",msg:{}},e.onChange=function(t){var a=t.target,n=a.value,s=a.name;e.setState(Object(N.a)({},s,n))},e.onSubmit=function(t){t.preventDefault();var a={login:e.state.login,mail:e.state.mail,pass:e.state.pass,pass2:e.state.pass2};e.props.register(a)},e}return Object(l.a)(a,[{key:"componentDidUpdate",value:function(e){if(!0===this.props.isAuth)return this.props.clearErrors(),this.props.history.push("/");var t=this.props.error;t!==e.error&&("REGISTER_FAIL"===t.id?this.setState({msg:t.msg}):this.setState({msg:{}}))}},{key:"componentWillUnmount",value:function(){this.props.clearErrors()}},{key:"render",value:function(){return s.a.createElement("div",{className:"register-section"},s.a.createElement("h2",{className:"log-title"},"Register"),s.a.createElement("div",{className:"flex-wrap center"},s.a.createElement("form",{onSubmit:this.onSubmit,className:"add-form",autoComplete:"off"},s.a.createElement("div",{className:"simple-input"},s.a.createElement("input",{type:"text",name:"login",placeholder:"Login",value:this.state.login,onChange:this.onChange,className:this.state.msg.login&&"error"})," ",this.state.msg.login&&s.a.createElement("div",{className:"exclam"},s.a.createElement("img",{src:"img/exclam-ico.png",alt:""}))),s.a.createElement("div",{className:"simple-input"},s.a.createElement("input",{type:"text",name:"mail",placeholder:"E-mail",value:this.state.mail,onChange:this.onChange,className:this.state.msg.mail&&"error"})," ",this.state.msg.mail&&s.a.createElement("div",{className:"exclam"},s.a.createElement("img",{src:"img/exclam-ico.png",alt:""}))),s.a.createElement("div",{className:"simple-input"},s.a.createElement("input",{type:"password",name:"pass",placeholder:"Password",value:this.state.pass,onChange:this.onChange,className:this.state.msg.pass&&"error"})," ",this.state.msg.pass&&s.a.createElement("div",{className:"exclam"},s.a.createElement("img",{src:"img/exclam-ico.png",alt:""}))),s.a.createElement("div",{className:"simple-input"},s.a.createElement("input",{type:"password",name:"pass2",placeholder:"Password Again",value:this.state.pass2,onChange:this.onChange,className:this.state.msg.pass2&&"error"})," ",this.state.msg.pass2&&s.a.createElement("div",{className:"exclam"},s.a.createElement("img",{src:"img/exclam-ico.png",alt:""}))),s.a.createElement("button",{type:"submit",className:"btn"},"Sign Up"))))}}]),a}(s.a.Component),C=Object(j.f)(Object(E.b)((function(e){return{isAuth:e.auth.isAuthenticated,error:e.error}}),{register:function(e){return function(t){var a=JSON.stringify(e);g.a.post("/user/register",a,{headers:{"Content-type":"application/json"}}).then((function(e){return t({type:"REGISTER_SUCCESS",payload:e.data})})).catch((function(e){t(p(e.response.data,e.response.status,"REGISTER_FAIL")),t({type:"REGISTER_FAIL"})}))}},clearErrors:h})(R)),x=a(20),w=Object(E.b)((function(e){return{isAuth:e.auth.isAuthenticated,user:e.auth.user,isLoading:e.auth.isLoading}}),null,null,{pure:!1})((function(e){var t=e.component,a=e.isAdmin,n=e.isAuth,r=e.user,i=e.isLoading,c=Object(x.a)(e,["component","isAdmin","isAuth","user","isLoading"]);return!i&&s.a.createElement(j.b,Object.assign({exact:!0},c,{render:function(e){return n?a.includes(r.isAdmin)?s.a.createElement(t,null):s.a.createElement(j.a,{to:"/"}):s.a.createElement(j.a,{to:"/login"})}}))})),I=Object(E.b)((function(e){return{isAuth:e.auth.isAuthenticated,isLoading:e.auth.isLoading}}),null,null,{pure:!1})((function(e){var t=e.component,a=e.isAuth,n=e.isLoading,r=Object(x.a)(e,["component","isAuth","isLoading"]);return!n&&s.a.createElement(j.b,Object.assign({exact:!0},r,{render:function(e){return a?s.a.createElement(j.a,{to:"/"}):s.a.createElement(t,null)}}))})),_=(a(73),a(14)),U=a(41),G=a(12),k={user:{},isAuthenticated:!1,isLoading:!1},T={msg:{},status:null,id:null},D=Object(_.c)({auth:function(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:k,t=arguments.length>1?arguments[1]:void 0;switch(t.type){case"USER_LOADING":return Object(G.a)(Object(G.a)({},e),{},{isLoading:!0});case"USER_LOADED":return Object(G.a)(Object(G.a)({},e),{},{isLoading:!1,isAuthenticated:!0,user:t.payload});case"LOGIN_SUCCESS":case"REGISTER_SUCCESS":return Object(G.a)(Object(G.a)({},e),{},{user:t.payload,isLoading:!1,isAuthenticated:!0});case"AUTH_ERROR":case"LOGIN_FAIL":case"REGISTER_FAIL":case"LOGOUT_SUCCESS":return Object(G.a)(Object(G.a)({},e),{},{isLoading:!1,isAuthenticated:!1,user:{}});default:return e}},error:function(){var e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:T,t=arguments.length>1?arguments[1]:void 0;switch(t.type){case"GET_ERRORS":return{msg:t.payload.msg,status:t.payload.status,id:t.payload.id};case"CLEAR_ERRORS":return{msg:{},status:null,id:null};default:return e}}}),F=[U.a],H=Object(_.d)(D,{},_.a.apply(void 0,F)),J=function(e){Object(o.a)(a,e);var t=Object(u.a)(a);function a(){return Object(c.a)(this,a),t.apply(this,arguments)}return Object(l.a)(a,[{key:"componentDidMount",value:function(){H.dispatch((function(e,t){e({type:"USER_LOADING"}),g.a.get("/user/info").then((function(t){e({type:"USER_LOADED",payload:t.data})})).catch((function(t){e(p(t.response.data,t.response.status,"AUTH_ERROR")),e({type:"AUTH_ERROR"})}))}))}},{key:"render",value:function(){return s.a.createElement(E.a,{store:H},s.a.createElement(m.a,null,s.a.createElement("div",{className:"wrapper"},s.a.createElement(b,null),s.a.createElement("div",{className:"content-section"},s.a.createElement("div",{className:"container"},s.a.createElement(w,{path:"/",isAdmin:[0,1],component:O}),s.a.createElement(w,{path:"/admin",isAdmin:[1],component:A}),s.a.createElement(I,{path:"/login",component:S}),s.a.createElement(I,{path:"/register",component:C}))))))}}]),a}(s.a.Component);Boolean("localhost"===window.location.hostname||"[::1]"===window.location.hostname||window.location.hostname.match(/^127(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}$/));i.a.render(s.a.createElement(s.a.StrictMode,null,s.a.createElement(J,null)),document.getElementById("root")),"serviceWorker"in navigator&&navigator.serviceWorker.ready.then((function(e){e.unregister()})).catch((function(e){console.error(e.message)}))}},[[42,1,2]]]);
//# sourceMappingURL=main.ac4e2a01.chunk.js.map