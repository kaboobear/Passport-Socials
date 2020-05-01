import React from 'react';
import {BrowserRouter as Router, Route} from 'react-router-dom';

import Header from './components/header'
import Main from './components/main'
import Admin from './components/admin'
import Login from './components/login'
import Register from './components/register'
import PrivateRoute from './hoc/privateRoute'
import UnprivateRoute from './hoc/unprivateRoute'
import './App.css';

import store from './store';
import {Provider} from 'react-redux';
import {loadUser} from './actions/authActions'

class App extends React.Component {
    componentDidMount() {
        store.dispatch(loadUser())
    }

    render() {
        return (
            <Provider store={store}>
                <Router>
                    <div className="wrapper">
                        <Header/>

                        <div className="content-section">
                            <div className="container">
                                {/* <Route path='/' exact component={Main}/>
                                <Route path='/admin' exact component={Admin}/>
                                <Route path='/login' exact component={Login}/>
                                <Route path='/register' exact component={Register}/> */}
                                <PrivateRoute path="/" isAdmin={[0,1]} component={Main}/>
                                <PrivateRoute path="/admin" isAdmin={[1]} component={Admin}/>
                                <UnprivateRoute path="/login" component={Login}/>
                                <UnprivateRoute path="/register" component={Register}/>

                            </div>
                        </div>
                    </div>
                </Router>
            </Provider>
        );
    }
}

export default App;
