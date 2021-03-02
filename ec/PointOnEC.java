package kpp.ec;

/*
 * 1) PointOnEC.class

Attribute

    public int x => X-Koordinate
    public int y => Y-Koordinate

Konstruktor

    public PointOnEC(int x, int y) => Setze die Attribute

Methoden

    public boolean equals(PointOnEC p) => Ergibt "true", falls die Koordinaten gleich sind
 */

public class PointOnEC {

	public int x, y;

	public PointOnEC(int x, int y) {
		this.x = x;
		this.y = y;
	}

	public PointOnEC(int infinity) {
		this.x = infinity;
		this.y = infinity;
	}

	public boolean equals(PointOnEC p) {
		return ((this.x == p.x) && (this.y == p.y));
	}

	public String toString() {
		return "x = " + x + ", y = " + y;
	}

}
