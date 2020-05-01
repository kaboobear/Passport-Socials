import React from 'react';
import {Route,Redirect} from 'react-router-dom';
import {connect} from 'react-redux';


const PrivateRoute = ({component:Component, isAuth, isLoading, ...rest})=>{
    return(
        (!isLoading) && (
        <Route exact {...rest} render={props=>{
            if(isAuth) return <Redirect to="/"/>
            return <Component/>
        }}/>)
    )
}

const mapStateToProps = state => ({isAuth: state.auth.isAuthenticated,isLoading:state.auth.isLoading})
export default connect(mapStateToProps, null, null, { pure: false, })(PrivateRoute);




