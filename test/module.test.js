"use strict";

const expect = require("chai").expect,
	strategy = require("..");

describe("cognito-express", function() {
	it("should export Strategy constructor directly from package", function() {
		expect(strategy).to.be.a("function");
		expect(strategy).to.equal(strategy.Strategy);
	});

	it("should export Strategy constructor", function() {
		expect(strategy.Strategy).to.be.a("function");
	});
});
