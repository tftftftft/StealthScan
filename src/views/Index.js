import React from "react";

// reactstrap components

import { Container, Row, Col } from "reactstrap";

// core components
import DemoNavbar from "components/Navbars/DemoNavbar.js";


// index page sections
import Hero from "./IndexSections/Hero.js";

class Index extends React.Component {
  componentDidMount() {
    document.documentElement.scrollTop = 0;
    document.scrollingElement.scrollTop = 0;
    this.refs.main.scrollTop = 0;
  }
  render() {
    return (
      <>
        <DemoNavbar />
        <main ref="main">
          <Hero />
          <section className="section">
            <Container>
              <Row className="justify-content-center">
                <Col md="4">
                  <div className="box">
                    <h3>Box 1</h3>
                    <p>Some text here...</p>
                  </div>
                </Col>
                <Col md="4">
                  <div className="box">
                    <h3>Box 2</h3>
                    <p>Some text here...</p>
                  </div>
                </Col>
                <Col md="4">
                  <div className="box">
                    <h3>Box 3</h3>
                    <p>Some text here...</p>
                  </div>
                </Col>
              </Row>
            </Container>
          </section>
        </main>
      </>
    );
  }
}

export default Index;
