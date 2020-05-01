import React from 'react';
import {Route,Redirect} from 'react-router-dom';
import {connect} from 'react-redux';


const PrivateRoute = ({component:Component,isAdmin, isAuth, user, isLoading, ...rest})=>{
    return(
        (!isLoading) && (
        <Route exact {...rest} render={props=>{
            if(!isAuth) return <Redirect to="/login"/>
            if(!isAdmin.includes(user.isAdmin)) return <Redirect to="/"/>
            return <Component/>
        }}/>)
    )
}

const mapStateToProps = state => ({isAuth: state.auth.isAuthenticated,user: state.auth.user,isLoading:state.auth.isLoading})
export default connect(mapStateToProps, null, null, { pure: false, })(PrivateRoute);




