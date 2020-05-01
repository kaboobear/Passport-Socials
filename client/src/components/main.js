import React, {Component} from 'react';
import {connect} from 'react-redux';
import {NavLink} from 'react-router-dom';

class Main extends Component {
    render() {
        const {isAuth, isLoading, items} = this.props;

        return (
            <div className="main-section">
                <h2>Dashboard ( {(isAuth)
                        ? (
                            <span>Logged In</span>
                        )
                        : (
                            <span>Logged Out</span>
                        )})</h2>

            </div>
        )
    }
}

const mapStateToProps = (state) => ({isAuth: state.auth.isAuthenticated,isLoading:state.auth.isLoading})
export default connect(mapStateToProps, {})(Main);