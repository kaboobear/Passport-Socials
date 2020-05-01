import React, {Component} from 'react';
import {connect} from 'react-redux';
import {NavLink} from 'react-router-dom';

class Admin extends Component {
    render() {
        const {isAuth} = this.props;

        return (
            <div className="main-section">
                <h2>Admin Panel</h2>
            </div>
        )
    }
}

const mapStateToProps = (state) => ({isAuth: state.auth.isAuthenticated,isLoading:state.auth.isLoading})
export default connect(mapStateToProps, {})(Admin);